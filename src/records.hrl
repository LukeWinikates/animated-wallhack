-record(secrets, {consumer_secret, oauth_token_secret}).
-record(request, {secrets, params, base_url, oauth_params, method}).
