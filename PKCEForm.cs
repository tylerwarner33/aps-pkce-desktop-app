using Autodesk.Authentication;
using Autodesk.Authentication.Model;
using Autodesk.SDKManager;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace PKCEForm;

public partial class PKCEForm : Form
{
	public static class Global
	{
		public static string? CodeVerifier { get; set; }

		public static string? ClientId { get; set; }

		public static string? CallbackURL { get; set; }

		public static ThreeLeggedToken? Token { get; set; }

		public static List<Scopes> Scopes =>
			[Autodesk.Authentication.Model.Scopes.DataRead, Autodesk.Authentication.Model.Scopes.DataWrite];
	}

	public static SDKManager SdkManager => SdkManagerBuilder.Create().Build();

	public static AuthenticationClient AuthenticationClient => new(SdkManager);

	public PKCEForm()
	{
		InitializeComponent();
	}

	private async void btn_Login_Click(object sender, EventArgs e)
	{
		try
		{
			lbl_Status.Text = "Opening browser for sign-in...";
			Global.ClientId = Properties.Resources.ClientId
				?? throw new InvalidOperationException("ClientId is not set in resources.");
			Global.CallbackURL = Properties.Resources.CallbackUrl
				?? throw new InvalidOperationException("CallbackUrl is not set in resources.");

			Global.CodeVerifier = CreateCodeVerifier(64);
			Global.Token = await GetAccessTokenAsync(Global.CodeVerifier);
		}
		catch (Exception ex)
		{
			lbl_Status.Text = "Login failed.";
			txt_Result.Text = ex.Message;
		}
	}

	/// <summary>
	///	Get a three-legged token.
	/// </summary>
	/// <remarks>
	///	References:
	///	<a href="https://aps.autodesk.com/en/docs/oauth/v2/tutorials/get-3-legged-token-pkce/get-3-legged-token-pkce/">
	///	Autodesk/Docs/Authentication/ThreeLeggedTokenPkce
	///	</a>
	///	<a href="https://github.com/autodesk-platform-services/aps-pkce-desktop-app">
	///	GitHub/Autodesk/PkceDesktopApp
	///	</a>
	/// </remarks>
	public async Task<ThreeLeggedToken> GetAccessTokenAsync(string codeVerifier)
	{
		try
		{
			string authorizationCode = await GetAuthorizationCode(codeVerifier);

			ThreeLeggedToken token = await AuthenticationClient.GetThreeLeggedTokenAsync(
				clientId: Global.ClientId,
				code: authorizationCode,
				redirectUri: Global.CallbackURL,
				codeVerifier: codeVerifier);

			return token;
		}
		catch (Exception ex)
		{
			throw;
		}
	}

	private async void btn_Refresh_Click(object sender, EventArgs eventArgs)
	{
		try
		{
			var token = await GetRefreshTokenAsync(Global.Token);

			lbl_Status.Text = "You can find your new token below";
			txt_Result.Text = token.AccessToken;
			Global.Token = token;
		}
		catch (Exception ex)
		{
			lbl_Status.Text = "An error occurred!";
			txt_Result.Text = ex.Message;
		}
	}

	/// <summary>
	///	Refresh a three-legged token.
	/// </summary>
	public async Task<ThreeLeggedToken> GetRefreshTokenAsync(ThreeLeggedToken threeLeggedToken)
	{
		try
		{
			ThreeLeggedToken token = await AuthenticationClient.RefreshTokenAsync(
				refreshToken: threeLeggedToken.RefreshToken,
				clientId: Global.ClientId,
				scopes: Global.Scopes);

			return token;
		}
		catch (Exception ex)
		{
			throw;
		}
	}

	/// <summary>
	///	Get the PKCE authorization code using HttpListener to login into Autodesk account with credentials.
	/// </summary>
	/// <remarks>	
	///	References:
	///	<a href="https://aps.autodesk.com/en/docs/oauth/v2/tutorials/get-3-legged-token-pkce/get-3-legged-token-pkce/">
	///	Autodesk/Docs/Authentication/ThreeLeggedTokenPkce
	///	</a>
	/// </remarks>
	private async Task<string> GetAuthorizationCode(string codeVerifier)
	{
		try
		{
			string codeChallenge = CreateCodeChallenge(codeVerifier);

			if (HttpListener.IsSupported is false)
				throw new NotSupportedException($"{nameof(HttpListener)} is not supported in this context.");

			// HttpListener requires a trailing slash in the prefix.
			string prefix = Global.CallbackURL.EndsWith('/')
				? Global.CallbackURL
				: Global.CallbackURL + "/";

			using HttpListener listener = new();
			listener.Prefixes.Add(prefix);
			listener.Start();

			var authUrl = AuthenticationClient.Authorize(
				clientId: Global.ClientId,
				responseType: ResponseType.Code,
				redirectUri: Global.CallbackURL, // Must exactly match the registered URL in your APS application.
				scopes: [Scopes.DataRead, Scopes.DataWrite],
				prompt: "login",
				codeChallenge: codeChallenge,
				codeChallengeMethod: "S256");

			Process.Start(new ProcessStartInfo(authUrl) { UseShellExecute = true });

			HttpListenerContext context = await listener.GetContextAsync().WaitAsync(TimeSpan.FromMinutes(5));

			var query = HttpUtility.ParseQueryString(context.Request.Url.Query);
			string authorizationCode = query["code"]
				?? throw new NullReferenceException($"Authorization code cannot be null.");

			byte[] buffer = Encoding.UTF8.GetBytes("<html><body>You can return to the app.</body></html>");
			await context.Response.OutputStream.WriteAsync(buffer);

			context.Response.Close();
			listener.Stop();

			return authorizationCode;
		}
		catch (TimeoutException ex)
		{
			lbl_Status.Text = "Timed out waiting for authorization.";
			txt_Result.Text = ex.Message;
			throw;
		}
		catch (HttpListenerException ex)
		{
			lbl_Status.Text = "Access is denied. Check for conflict on local URL ACL list.";
			txt_Result.Text = ex.Message;
			throw;
		}
		catch (Exception ex)
		{
			lbl_Status.Text = "An error occurred!";
			txt_Result.Text = ex.Message;
			throw;
		}
	}

	/// <summary>
	///	Random string between 43 and 128 characters and must contain only alphanumeric characters and punctuation characters -, ., _, ~.
	/// </summary>
	/// <remarks>
	///	<a href="https://aps.autodesk.com/en/docs/oauth/v2/tutorials/code-challenge/">
	///   APS/Docs/CodeChallenge
	///   </a>
	/// </remarks>
	private static string CreateCodeChallenge(string codeVerifier)
	{
		var hash = SHA256.HashData(Encoding.UTF8.GetBytes(codeVerifier));
		return Convert.ToBase64String(hash)
		  .TrimEnd('=')
		  .Replace('+', '-')
		  .Replace('/', '_');
	}

	/// <summary>
	///	Random string between 43 and 128 characters and must contain only alphanumeric characters and punctuation characters -, ., _, ~.
	/// </summary>
	/// <remarks>
	///	<a href="https://aps.autodesk.com/en/docs/oauth/v2/tutorials/code-challenge/">
	///   APS/Docs/CodeChallenge
	///   </a>
	/// </remarks>
	public static string CreateCodeVerifier(int length)
	{
		if (length is < 43 or > 128)
			throw new ArgumentOutOfRangeException(nameof(length), "PKCE code verifier length must be between 43 and 128 characters.");

		const string allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
		return RandomNumberGenerator.GetString(allowed.ToCharArray(), length);
	}
}
