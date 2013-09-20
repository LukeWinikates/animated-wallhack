-module(tc_signing).

-include("records.hrl").

-include_lib("eunit/include/eunit.hrl").

-export([signature/1]).

signing_key(Secrets) ->
  signing_key(Secrets#secrets.consumer_secret, Secrets#secrets.oauth_token_secret).

signing_key(ConsumerSecret, OAuthTokenSecret) ->
  ConsumerSecret ++ "&" ++ OAuthTokenSecret.

signature(Request) ->
  Key = signing_key(Request#request.secrets),
  Str = base_string(Request),
  Hmac = crypto:hmac(sha, Key, Str),
  base64:encode_to_string(Hmac).

joinparams([], _Separator, Acc) ->
  Acc;

joinparams([S | Rest], Separator, []) ->
  joinparams(Rest, Separator, S);

joinparams([S | Rest], Separator, Acc) ->
  New = Acc ++ Separator ++ S,
  joinparams(Rest, Separator, New).

joinparams(All) ->
  joinparams(All, "&", []).

parameter_string(Request) ->
  Sorted = lists:sort(request_params(Request)),
  Encoded = lists:map(fun(Param)->
        {A,B} = Param,
        K = erlang:atom_to_list(A),
        V = percent_encode(B),
        K ++ "=" ++ V end, Sorted),
  joinparams(Encoded).

percent_encode(Str) ->
  case Str of
    [32|Rest] ->
      "%20" ++ percent_encode(Rest);
    [$+|Rest] ->
      "%2B" ++ percent_encode(Rest);
    [$,|Rest] ->
      "%2C" ++ percent_encode(Rest);
    [$!|Rest] ->
      "%21" ++ percent_encode(Rest);
    [$:|Rest] ->
      "%3A" ++ percent_encode(Rest);
    [$/|Rest] ->
      "%2F" ++ percent_encode(Rest);
    [$=|Rest] ->
      "%3D" ++ percent_encode(Rest);
    [$&|Rest] ->
      "%26" ++ percent_encode(Rest);
    [$%|Rest] ->
      "%25" ++ percent_encode(Rest);
    [T|Rest] ->
      [T] ++ percent_encode(Rest);
    [] -> []
  end.

base_string(Request) ->
  "POST&" ++ percent_encode(Request#request.base_url) ++ "&" ++ percent_encode(parameter_string(Request)).

request_params(Request) ->
    Request#request.params ++ Request#request.oauth_params.

parameter_string_test() ->
  Request = test_request(),
  ParameterString = parameter_string(Request),
  ?assertMatch("include_entities=true&oauth_consumer_key=xvz1evFS4wEEPTGEFPHBog&oauth_nonce=kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1318622958&oauth_token=370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb&oauth_version=1.0&status=Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%20OAuth%20request%21", ParameterString).

signature_base_string_test() ->
  BaseString = base_string(test_request()),
  ?assertMatch("POST&https%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521", BaseString).

signing_key_test() ->
  Secrets = #secrets{consumer_secret="kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw",
    oauth_token_secret="LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE"},
  "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw&LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE" = signing_key(Secrets).

test_request()->
  Secrets = #secrets{consumer_secret="kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw",
    oauth_token_secret="LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE"},
  Params = [{status, "Hello Ladies + Gentlemen, a signed OAuth request!"},
    {include_entities, "true"}],
  OAuthParams=[{oauth_consumer_key, "xvz1evFS4wEEPTGEFPHBog"},
    {oauth_nonce, "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg"},
    {oauth_signature_method, "HMAC-SHA1"},
    {oauth_timestamp, "1318622958"},
    {oauth_token, "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb"},
    {oauth_version, "1.0"}],
  Url = "https://api.twitter.com/1/statuses/update.json",
  #request{secrets=Secrets, params=Params, oauth_params=OAuthParams, base_url=Url}.

signature_test() ->
  Request = test_request(),
  ?assertMatch("tnnArxj06cWHq44gCs1OSKk/jLY=", signature(Request)).

percent_encode_test() ->
  ?assertMatch("Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%20OAuth%20request%21", percent_encode("Hello Ladies + Gentlemen, a signed OAuth request!")).
