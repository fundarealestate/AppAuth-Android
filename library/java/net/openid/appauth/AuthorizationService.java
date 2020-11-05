/*
 * Copyright 2015 The AppAuth for Android Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.openid.appauth;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.AsyncTask;
import android.text.TextUtils;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;

import net.openid.appauth.AuthorizationException.GeneralErrors;
import net.openid.appauth.AuthorizationException.RegistrationRequestErrors;
import net.openid.appauth.AuthorizationException.TokenRequestErrors;
import net.openid.appauth.IdToken.IdTokenException;
import net.openid.appauth.connectivity.ConnectionBuilder;
import net.openid.appauth.internal.Logger;
import net.openid.appauth.internal.UriUtil;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URLConnection;
import java.util.Map;

import static net.openid.appauth.Preconditions.checkNotNull;

public class AuthorizationService {

    @VisibleForTesting
    Context mContext;

    @NonNull
    private final AppAuthConfiguration mClientConfiguration;

    /**
     * Constructor that injects a url builder into the service for testing.
     */
    @VisibleForTesting
    AuthorizationService(@NonNull Context context,
                         @NonNull AppAuthConfiguration clientConfiguration) {
        mContext = checkNotNull(context);
        mClientConfiguration = clientConfiguration;
    }

    /**
     * Sends an authorization request to the authorization service, using a
     * [custom tab](https://developer.chrome.com/multidevice/android/customtabs).
     * The parameters of this request are determined by both the authorization service
     * configuration and the provided {@link AuthorizationRequest request object}. Upon completion
     * of this request, the provided {@link PendingIntent completion PendingIntent} will be invoked.
     * If the user cancels the authorization request, the provided
     * {@link PendingIntent cancel PendingIntent} will be invoked.
     *
     * @throws android.content.ActivityNotFoundException if no suitable browser is available to
     *     perform the authorization flow.
     */
    public void performAuthorizationRequest(
            @NonNull AuthorizationRequest request,
            @NonNull PendingIntent completedIntent,
            @Nullable PendingIntent canceledIntent) {
        checkNotNull(request);
        checkNotNull(completedIntent);

        Intent authIntent = prepareAuthorizationRequestIntent(request);
        mContext.startActivity(AuthorizationManagementActivity.createStartIntent(
                mContext,
                request,
                authIntent,
                completedIntent,
                canceledIntent));
    }

    /**
     * Constructs an intent that encapsulates the provided request and custom tabs intent,
     * and is intended to be launched via {@link Activity#startActivityForResult}.
     * The parameters of this request are determined by both the authorization service
     * configuration and the provided {@link AuthorizationRequest request object}. Upon completion
     * of this request, the activity that gets launched will call {@link Activity#setResult} with
     * {@link Activity#RESULT_OK} and an {@link Intent} containing authorization completion
     * information. If the user presses the back button or closes the browser tab, the launched
     * activity will call {@link Activity#setResult} with
     * {@link Activity#RESULT_CANCELED} without a data {@link Intent}. Note that
     * {@link Activity#RESULT_OK} indicates the authorization request completed,
     * not necessarily that it was a successful authorization.
     *
     * @throws android.content.ActivityNotFoundException if no suitable browser is available to
     *     perform the authorization flow.
     */
    public Intent getAuthorizationRequestIntent(
            @NonNull AuthorizationRequest request) {

        Intent authIntent = prepareAuthorizationRequestIntent(request);
        return AuthorizationManagementActivity.createStartForResultIntent(
                mContext,
                request,
                authIntent);
    }

    /**
     * Sends a request to the authorization service to exchange a code granted as part of an
     * authorization request for a token. The result of this request will be sent to the provided
     * callback handler.
     */
    public void performTokenRequest(
            @NonNull TokenRequest request,
            @NonNull TokenResponseCallback callback) {
        performTokenRequest(request, NoClientAuthentication.INSTANCE, callback);
    }

    /**
     * Sends a request to the authorization service to exchange a code granted as part of an
     * authorization request for a token. The result of this request will be sent to the provided
     * callback handler.
     */
    public void performTokenRequest(
            @NonNull TokenRequest request,
            @NonNull ClientAuthentication clientAuthentication,
            @NonNull TokenResponseCallback callback) {
        Logger.debug("Initiating code exchange request to %s",
                request.configuration.tokenEndpoint);
        new TokenRequestTask(
                request,
                clientAuthentication,
                mClientConfiguration.getConnectionBuilder(),
                SystemClock.INSTANCE,
                callback)
                .execute();
    }

    /**
     * Sends a request to the authorization service to dynamically register a client.
     * The result of this request will be sent to the provided callback handler.
     */
    public void performRegistrationRequest(
            @NonNull RegistrationRequest request,
            @NonNull RegistrationResponseCallback callback) {
        Logger.debug("Initiating dynamic client registration %s",
                request.configuration.registrationEndpoint.toString());
        new RegistrationRequestTask(
                request,
                mClientConfiguration.getConnectionBuilder(),
                callback)
                .execute();
    }

    private Intent prepareAuthorizationRequestIntent(AuthorizationRequest request) {
        Uri requestUri = request.toUri();
        Intent intent = new Intent(Intent.ACTION_VIEW);
        intent.setData(requestUri);
        Logger.debug("Initiating authorization request to %s",
                request.configuration.authorizationEndpoint);

        return intent;
    }

    private static class TokenRequestTask
            extends AsyncTask<Void, Void, JSONObject> {

        private final TokenRequest mRequest;
        private final ClientAuthentication mClientAuthentication;
        private final ConnectionBuilder mConnectionBuilder;
        private final TokenResponseCallback mCallback;
        private final Clock mClock;

        private AuthorizationException mException;

        TokenRequestTask(TokenRequest request,
                         @NonNull ClientAuthentication clientAuthentication,
                         @NonNull ConnectionBuilder connectionBuilder,
                         Clock clock,
                         TokenResponseCallback callback) {
            mRequest = request;
            mClientAuthentication = clientAuthentication;
            mConnectionBuilder = connectionBuilder;
            mClock = clock;
            mCallback = callback;
        }

        @Override
        protected JSONObject doInBackground(Void... voids) {
            InputStream is = null;
            try {
                HttpURLConnection conn = mConnectionBuilder.openConnection(
                        mRequest.configuration.tokenEndpoint);
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
                addJsonToAcceptHeader(conn);
                conn.setDoOutput(true);

                Map<String, String> headers = mClientAuthentication
                        .getRequestHeaders(mRequest.clientId);
                if (headers != null) {
                    for (Map.Entry<String,String> header : headers.entrySet()) {
                        conn.setRequestProperty(header.getKey(), header.getValue());
                    }
                }

                Map<String, String> parameters = mRequest.getRequestParameters();
                Map<String, String> clientAuthParams = mClientAuthentication
                        .getRequestParameters(mRequest.clientId);
                if (clientAuthParams != null) {
                    parameters.putAll(clientAuthParams);
                }

                String queryData = UriUtil.formUrlEncode(parameters);
                conn.setRequestProperty("Content-Length", String.valueOf(queryData.length()));
                OutputStreamWriter wr = new OutputStreamWriter(conn.getOutputStream());

                wr.write(queryData);
                wr.flush();

                if (conn.getResponseCode() >= HttpURLConnection.HTTP_OK
                        && conn.getResponseCode() < HttpURLConnection.HTTP_MULT_CHOICE) {
                    is = conn.getInputStream();
                } else {
                    is = conn.getErrorStream();
                }
                String response = Utils.readInputStream(is);
                return new JSONObject(response);
            } catch (IOException ex) {
                Logger.debugWithStack(ex, "Failed to complete exchange request");
                mException = AuthorizationException.fromTemplate(
                        GeneralErrors.NETWORK_ERROR, ex);
            } catch (JSONException ex) {
                Logger.debugWithStack(ex, "Failed to complete exchange request");
                mException = AuthorizationException.fromTemplate(
                        GeneralErrors.JSON_DESERIALIZATION_ERROR, ex);
            } finally {
                Utils.closeQuietly(is);
            }
            return null;
        }

        @Override
        protected void onPostExecute(JSONObject json) {
            if (mException != null) {
                mCallback.onTokenRequestCompleted(null, mException);
                return;
            }

            if (json.has(AuthorizationException.PARAM_ERROR)) {
                AuthorizationException ex;
                try {
                    String error = json.getString(AuthorizationException.PARAM_ERROR);
                    ex = AuthorizationException.fromOAuthTemplate(
                            TokenRequestErrors.byString(error),
                            error,
                            json.optString(AuthorizationException.PARAM_ERROR_DESCRIPTION, null),
                            UriUtil.parseUriIfAvailable(
                                    json.optString(AuthorizationException.PARAM_ERROR_URI)));
                } catch (JSONException jsonEx) {
                    ex = AuthorizationException.fromTemplate(
                            GeneralErrors.JSON_DESERIALIZATION_ERROR,
                            jsonEx);
                }
                mCallback.onTokenRequestCompleted(null, ex);
                return;
            }

            TokenResponse response;
            try {
                response = new TokenResponse.Builder(mRequest).fromResponseJson(json).build();
            } catch (JSONException jsonEx) {
                mCallback.onTokenRequestCompleted(null,
                        AuthorizationException.fromTemplate(
                                GeneralErrors.JSON_DESERIALIZATION_ERROR,
                                jsonEx));
                return;
            }

            if (response.idToken != null) {
                IdToken idToken;
                try {
                    idToken = IdToken.from(response.idToken);
                } catch (IdTokenException | JSONException ex) {
                    mCallback.onTokenRequestCompleted(null,
                            AuthorizationException.fromTemplate(
                                    GeneralErrors.ID_TOKEN_PARSING_ERROR,
                                    ex));
                    return;
                }

                try {
                    idToken.validate(mRequest, mClock);
                } catch (AuthorizationException ex) {
                    mCallback.onTokenRequestCompleted(null, ex);
                    return;
                }
            }
            Logger.debug("Token exchange with %s completed",
                    mRequest.configuration.tokenEndpoint);
            mCallback.onTokenRequestCompleted(response, null);
        }

        /**
         * GitHub will only return a spec-compliant response if JSON is explicitly defined
         * as an acceptable response type. As this is essentially harmless for all other
         * spec-compliant IDPs, we add this header if no existing Accept header has been set
         * by the connection builder.
         */
        private void addJsonToAcceptHeader(URLConnection conn) {
            if (TextUtils.isEmpty(conn.getRequestProperty("Accept"))) {
                conn.setRequestProperty("Accept", "application/json");
            }
        }
    }

    /**
     * Callback interface for token endpoint requests.
     * @see AuthorizationService#performTokenRequest
     */
    public interface TokenResponseCallback {
        /**
         * Invoked when the request completes successfully or fails.
         *
         * Exactly one of `response` or `ex` will be non-null. If `response` is `null`, a failure
         * occurred during the request. This can happen if a bad URI was provided, no connection
         * to the server could be established, or the response JSON was incomplete or incorrectly
         * formatted.
         *
         * @param response the retrieved token response, if successful; `null` otherwise.
         * @param ex a description of the failure, if one occurred: `null` otherwise.
         *
         * @see AuthorizationException.TokenRequestErrors
         */
        void onTokenRequestCompleted(@Nullable TokenResponse response,
                @Nullable AuthorizationException ex);
    }

    private static class RegistrationRequestTask
            extends AsyncTask<Void, Void, JSONObject> {
        private final RegistrationRequest mRequest;
        private final ConnectionBuilder mConnectionBuilder;
        private final RegistrationResponseCallback mCallback;

        private AuthorizationException mException;

        RegistrationRequestTask(RegistrationRequest request,
                ConnectionBuilder connectionBuilder,
                RegistrationResponseCallback callback) {
            mRequest = request;
            mConnectionBuilder = connectionBuilder;
            mCallback = callback;
        }

        @Override
        protected JSONObject doInBackground(Void... voids) {
            InputStream is = null;
            String postData = mRequest.toJsonString();
            try {
                HttpURLConnection conn = mConnectionBuilder.openConnection(
                        mRequest.configuration.registrationEndpoint);
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setDoOutput(true);
                conn.setRequestProperty("Content-Length", String.valueOf(postData.length()));
                OutputStreamWriter wr = new OutputStreamWriter(conn.getOutputStream());
                wr.write(postData);
                wr.flush();

                is = conn.getInputStream();
                String response = Utils.readInputStream(is);
                return new JSONObject(response);
            } catch (IOException ex) {
                Logger.debugWithStack(ex, "Failed to complete registration request");
                mException = AuthorizationException.fromTemplate(
                        GeneralErrors.NETWORK_ERROR, ex);
            } catch (JSONException ex) {
                Logger.debugWithStack(ex, "Failed to complete registration request");
                mException = AuthorizationException.fromTemplate(
                        GeneralErrors.JSON_DESERIALIZATION_ERROR, ex);
            } finally {
                Utils.closeQuietly(is);
            }
            return null;
        }

        @Override
        protected void onPostExecute(JSONObject json) {
            if (mException != null) {
                mCallback.onRegistrationRequestCompleted(null, mException);
                return;
            }

            if (json.has(AuthorizationException.PARAM_ERROR)) {
                AuthorizationException ex;
                try {
                    String error = json.getString(AuthorizationException.PARAM_ERROR);
                    ex = AuthorizationException.fromOAuthTemplate(
                            RegistrationRequestErrors.byString(error),
                            error,
                            json.getString(AuthorizationException.PARAM_ERROR_DESCRIPTION),
                            UriUtil.parseUriIfAvailable(
                                    json.getString(AuthorizationException.PARAM_ERROR_URI)));
                } catch (JSONException jsonEx) {
                    ex = AuthorizationException.fromTemplate(
                            GeneralErrors.JSON_DESERIALIZATION_ERROR,
                            jsonEx);
                }
                mCallback.onRegistrationRequestCompleted(null, ex);
                return;
            }

            RegistrationResponse response;
            try {
                response = new RegistrationResponse.Builder(mRequest)
                        .fromResponseJson(json).build();
            } catch (JSONException jsonEx) {
                mCallback.onRegistrationRequestCompleted(null,
                        AuthorizationException.fromTemplate(
                                GeneralErrors.JSON_DESERIALIZATION_ERROR,
                                jsonEx));
                return;
            } catch (RegistrationResponse.MissingArgumentException ex) {
                Logger.errorWithStack(ex, "Malformed registration response");
                mException = AuthorizationException.fromTemplate(
                        GeneralErrors.INVALID_REGISTRATION_RESPONSE,
                        ex);
                return;
            }
            Logger.debug("Dynamic registration with %s completed",
                    mRequest.configuration.registrationEndpoint);
            mCallback.onRegistrationRequestCompleted(response, null);
        }
    }

    /**
     * Callback interface for token endpoint requests.
     *
     * @see AuthorizationService#performTokenRequest
     */
    public interface RegistrationResponseCallback {
        /**
         * Invoked when the request completes successfully or fails.
         *
         * Exactly one of `response` or `ex` will be non-null. If `response` is `null`, a failure
         * occurred during the request. This can happen if an invalid URI was provided, no
         * connection to the server could be established, or the response JSON was incomplete or
         * incorrectly formatted.
         *
         * @param response the retrieved registration response, if successful; `null` otherwise.
         * @param ex a description of the failure, if one occurred: `null` otherwise.
         * @see AuthorizationException.RegistrationRequestErrors
         */
        void onRegistrationRequestCompleted(@Nullable RegistrationResponse response,
                                            @Nullable AuthorizationException ex);
    }
}
