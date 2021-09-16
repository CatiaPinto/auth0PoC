package com.auth0.example;

import com.auth0.AuthenticationController;
import com.auth0.IdentityVerificationException;
import com.auth0.SessionUtils;
import com.auth0.Tokens;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Base64;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * The Servlet endpoint used as the callback handler in the OAuth 2.0 authorization code grant flow. It will be called
 * with the authorization code after a successful login.
 */
@WebServlet(urlPatterns = {"/callback"})
public class CallbackServlet extends HttpServlet {

    private String redirectOnSuccess;
    private String redirectOnFail;
    private AuthenticationController authenticationController;


    /**
     * Initialize this servlet with required configuration.
     * <p>
     * Parameters needed on the Local Servlet scope:
     * <ul>
     * <li>'com.auth0.redirect_on_success': where to redirect after a successful authentication.</li>
     * <li>'com.auth0.redirect_on_error': where to redirect after a failed authentication.</li>
     * </ul>
     * Parameters needed on the Local/Global Servlet scope:
     * <ul>
     * <li>'com.auth0.domain': the Auth0 domain.</li>
     * <li>'com.auth0.client_id': the Auth0 Client id.</li>
     * <li>'com.auth0.client_secret': the Auth0 Client secret.</li>
     * </ul>
     */
    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        redirectOnSuccess = "/portal/home";
        redirectOnFail = "/login";

        try {
            authenticationController = AuthenticationControllerProvider.getInstance(config);
        } catch (UnsupportedEncodingException e) {
            throw new ServletException(
                "Couldn't create the AuthenticationController instance. Check the configuration.", e);
        }
    }

    /**
     * Process a call to the redirect_uri with a GET HTTP method.
     *
     * @param req the received request with the tokens (implicit grant) or the authorization code (code grant) in the
     *            parameters.
     * @param res the response to send back to the server.
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {
        handle(req, res);
    }


    /**
     * Process a call to the redirect_uri with a POST HTTP method. This occurs if the authorize_url included the
     * 'response_mode=form_post' value. This is disabled by default. On the Local Servlet scope you can specify the
     * 'com.auth0.allow_post' parameter to enable this behaviour.
     *
     * @param req the received request with the tokens (implicit grant) or the authorization code (code grant) in the
     *            parameters.
     * @param res the response to send back to the server.
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {
        handle(req, res);
    }

    private void handle(HttpServletRequest req, HttpServletResponse res) throws IOException {
        try {
            Tokens tokens = authenticationController.handle(req, res);
            SessionUtils.set(req, "accessToken", tokens.getAccessToken());
            SessionUtils.set(req, "idToken", tokens.getIdToken());
            playingJWT(tokens.getIdToken());
            res.sendRedirect(redirectOnSuccess);
            System.out.println("Access token -> " + tokens.getAccessToken());
            //this is the JWT
            //example :  eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InEzV1BiV2V4UlVDbEdreDBuOEdpayJ9
            // .eyJpc3MiOiJodHRwczovL2Rldi01ZzVnMzF4Mi51cy5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8NjE0MWY3YjJjNmJjNTYwMDY5NjRjN2RiIiwiYXVkIjoia2MzbnZxQlJ2VGRGdWZ4T3VBVVJodHlVOFNScG5lTFAiLCJpYXQiOjE2MzE3MTQxMTAsImV4cCI6MTYzMTc1MDExMH0.aG0GsicJdJabg4PLzV_s1lR9tMzPJYSWsr7Uqi2XFm8sxcrgddoPRXzhCjoKiRqoAnAVWi_yFkHADe-McRNWklUkbbsL-DG03eHbk-NuM2e8ox_GsO9UAACJophbFp3wsjR9O2LTRkY4n6-OFqHELHpsk5A6kLdkOf5RIKsF077ILZqeglATTZupZkqd2eG9LkQCCGt_XYS85pTEdrYcyLnsEFCxBKXI1pj6YS3O4h14QxkvhP0vNgHaXMIaTt0aiZYvn1-9kYqAdYxbvmezq-WfjO9lYQAHV1PJRNH51wOUV5_gTtlMag-HgwZM8NaZ3dqauh0wygDVEDBCCLmakw
            System.out.println("idToken -> " + tokens.getIdToken());
        } catch (IdentityVerificationException e) {
            e.printStackTrace();
            res.sendRedirect(redirectOnFail);
        }
    }

    private void playingJWT(String token) {
        //because the token doesn't have a public key to decode the token, is just the base64
        String[] jWTComponents = token.split("\\.");
        Base64.Decoder decoder = Base64.getDecoder();

        String header = new String(decoder.decode(jWTComponents[0]));
        String payload = new String(decoder.decode(jWTComponents[1]));
        System.out.println("Header -> " + header);
        System.out.println("payload -> " + payload);

        //guessing in the future we will need something like
//        Algorithm algorithm = Algorithm.RSA256(publicKey, privateKey);
//        JWTVerifier verifier = JWT.require(algorithm)
//            .withIssuer("auth0")
//            .build(); //Reusable verifier instance
//        DecodedJWT jwt = verifier.verify(token);
//        Claim claim = jwt.getHeaderClaim("owner");
    }
}
