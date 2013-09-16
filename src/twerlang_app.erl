-module(twerlang_app).

-behaviour(application).

%% Application callbacks
-export([start/2, stop/1]).

-export([uri_encode/1]).

-include_lib("eunit/include/eunit.hrl").

%% ===================================================================
%% Application callbacks
%% ===================================================================
start(_StartType, _StartArgs) ->
  crypto:start(),
  twerlang_sup:start_link().

stop(_State) ->
  crypto:stop(),
  ok.

-record(secrets, {oauth_consumer_key, oauth_token}).
-record(request, {secrets, params}).

signing_key(Secrets) ->
  signing_key(Secrets#secrets.oauth_consumer_key, Secrets#secrets.oauth_token).

signing_key(ConsumerSecret, OAuthTokenSecret) ->
  ConsumerSecret ++ "&" ++ OAuthTokenSecret.

signature(Request) ->
  Key = signing_key(Request#request.secrets),
  Str = parameter_string(Request),
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
        V = edoc_lib:escape_uri(B),
        K ++ "=" ++ V end, Sorted),
  joinparams(Encoded).

uri_encode(Str) ->
  Map = lists:map(fun(C)-> encode_char(C) end, Str),
  lists:concat(Map).

encode_char(C) ->
  case C of
    $! -> "%21";
    " " -> "%20";
    _Else -> C
  end.

request_params(Request) ->
  Secrets = Request#request.secrets,
   [{ oauth_consumer_key, Secrets#secrets.oauth_consumer_key} |
    [{oauth_token, Secrets#secrets.oauth_token}|Request#request.params]].

parameter_string_test() ->
  Request = test_request(),
  ParameterString = "\"" ++ parameter_string(Request) ++ "\"",
  ?assertMatch("include_entities=true&oauth_consumer_key=xvz1evFS4wEEPTGEFPHBog&oauth_nonce=kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1318622958&oauth_token=370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb&oauth_version=1.0&status=Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%20OAuth%20request%21", ParameterString).

signing_key_test() ->
  Secrets = #secrets{oauth_consumer_key="kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw",
    oauth_token="LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE"},
  "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw&LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE" = signing_key(Secrets).

test_request()->
  Secrets = #secrets{oauth_consumer_key="xvz1evFS4wEEPTGEFPHBog",
    oauth_token="370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb"},
  Params = [{status, "Hello Ladies + Gentlemen, a signed OAuth request!"},
    {include_entities, "true"},
    {oauth_nonce, "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg"},
    {oauth_signature_method, "HMAC-SHA1"},
    {oauth_timestamp, "1318622958"},
    {oauth_version, "1.0"}],
  #request{secrets=Secrets, params=Params}.

signature_test() ->
  Request = test_request(),
  ?assertMatch("tnnArxj06cWHq44gCs1OSKk/jLY=", signature(Request)).

uri_encode_test() ->
  Encoded = uri_encode("Hello Ladies + Gentlemen, a signed OAuth request!"),
  ?assertMatch("Hello%20Ladies%20%2b%20Gentlemen%2c%20a%20signed%20OAuth%20request%21", Encoded).
