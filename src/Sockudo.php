<?php

namespace Sockudo;

use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\GuzzleException;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Promise\PromiseInterface;

class Sockudo implements LoggerAwareInterface, SockudoInterface
{
    use LoggerAwareTrait;

    /**
     * @var string Version
     */
    public static $VERSION = '7.2.6';

    /**
     * @var null|SockudoCrypto
     */
    private $crypto;

    /**
     * @var string 16-char base64url identifier for deterministic idempotency keys.
     */
    private string $baseId;

    /**
     * @var int Monotonic counter for deterministic idempotency keys.
     * Incremented before each publish call.
     */
    private int $publishSerial = 0;

    /**
     * @var int Maximum number of retry attempts for network/5xx errors.
     */
    private int $maxRetries = 3;

    /**
     * @var array Settings
     */
    private $settings = [
        'scheme'                => 'http',
        'port'                  => 80,
        'path'                  => '',
        'timeout'               => 30,
        'auto_idempotency_key'  => true,
    ];

    /**
     * @var null|resource
     */
    private $client = null; // Guzzle client

    /**
     * Initializes a new Sockudo instance with key, secret, app ID and channel.
     *
     * @param string $auth_key
     * @param string $secret
     * @param string $app_id
     * @param array $options  [optional]
     *                         Options to configure the Sockudo instance.
     *                         scheme - e.g. http or https
     *                         host - the host e.g. localhost. No trailing forward slash.
     *                         port - the http port
     *                         timeout - the http timeout
     *                         useTLS - quick option to use scheme of https and port 443 (default is true).
     *                         cluster - cluster name to connect to.
     *                         encryption_master_key_base64 - a 32 byte key, encoded as base64. This key, along with the channel name, are used to derive per-channel encryption keys. Per-channel keys are used to encrypt event data on encrypted channels.
     * @param ClientInterface|null $client [optional] - a Guzzle client to use for all HTTP requests
     *
     * @throws SockudoException Throws exception if any required dependencies are missing
     */
    public function __construct(string $auth_key, string $secret, string $app_id, array $options = [], ?ClientInterface $client = null)
    {
        $this->check_compatibility();

        $useTLS = true;
        if (isset($options['useTLS'])) {
            $useTLS = $options['useTLS'] === true;
        }
        if (
            $useTLS &&
            !isset($options['scheme']) &&
            !isset($options['port'])
        ) {
            $options['scheme'] = 'https';
            $options['port'] = 443;
        }

        $this->baseId = rtrim(strtr(base64_encode(random_bytes(12)), '+/', '-_'), '=');

        $this->settings['auth_key'] = $auth_key;
        $this->settings['secret'] = $secret;
        $this->settings['app_id'] = $app_id;
        $this->settings['base_path'] = '/apps/' . $this->settings['app_id'];

        foreach ($options as $key => $value) {
            // only set if valid setting/option
            if (isset($this->settings[$key])) {
                $this->settings[$key] = $value;
            }
        }

        // handle the case when 'host' and 'cluster' are specified in the options.
        if (!array_key_exists('host', $this->settings)) {
            if (array_key_exists('host', $options)) {
                $this->settings['host'] = $options['host'];
            } elseif (array_key_exists('cluster', $options)) {
                $this->settings['host'] = 'api-' . $options['cluster'] . '.sockudo.com';
            } else {
                $this->settings['host'] = 'localhost';
            }
        }

        // ensure host doesn't have a scheme prefix
        $this->settings['host'] = preg_replace('/http[s]?\:\/\//', '', $this->settings['host'], 1);

        if (!array_key_exists('encryption_master_key_base64', $options)) {
            $options['encryption_master_key_base64'] = '';
        }

        if ($options['encryption_master_key_base64'] !== '') {
            $parsedKey = SockudoCrypto::parse_master_key(
                $options['encryption_master_key_base64']
            );
            $this->crypto = new SockudoCrypto($parsedKey);
        }


        if (!is_null($client)) {
            $this->client = $client;
        } else {
            $this->client = new \GuzzleHttp\Client(['timeout'  => $this->settings['timeout'],]);
        }
    }

    /**
     * Fetch the settings.
     *
     * @return array
     */
    public function getSettings(): array
    {
        return $this->settings;
    }

    /**
     * Log a string.
     *
     * @param string           $msg     The message to log
     * @param array|\Exception $context [optional] Any extraneous information that does not fit well in a string.
     * @param string           $level   [optional] Importance of log message, highly recommended to use Psr\Log\LogLevel::{level}
     */
    private function log(string $msg, array $context = [], string $level = LogLevel::DEBUG): void
    {
        if (is_null($this->logger)) {
            return;
        }

        if ($this->logger instanceof LoggerInterface) {
            $this->logger->log($level, $msg, $context);

            return;
        }

        // Support old style logger (deprecated)
        $msg = sprintf('Sockudo: %s: %s', strtoupper($level), $msg);
        $replacement = [];

        foreach ($context as $k => $v) {
            $replacement['{' . $k . '}'] = $v;
        }

        $this->logger->log($level, strtr($msg, $replacement));
    }

    /**
     * Check if the current PHP setup is sufficient to run this class.
     *
     * @throws SockudoException If any required dependencies are missing
     */
    private function check_compatibility(): void
    {
        if (!extension_loaded('json')) {
            throw new SockudoException('The Sockudo library requires the PHP JSON module. Please ensure it is installed');
        }

        if (!in_array('sha256', hash_algos(), true)) {
            throw new SockudoException('SHA256 appears to be unsupported - make sure you have support for it, or upgrade your version of PHP.');
        }
    }

    /**
     * Validate number of channels and channel name format.
     *
     * @param string[] $channels An array of channel names to validate
     *
     * @throws SockudoException If $channels is too big or any channel is invalid
     */
    private function validate_channels(array $channels): void
    {
        if (count($channels) > 100) {
            throw new SockudoException('An event can be triggered on a maximum of 100 channels in a single call.');
        }

        foreach ($channels as $channel) {
            $this->validate_channel($channel);
        }
    }

    /**
     * Ensure a channel name is valid based on our spec.
     *
     * @param string $channel The channel name to validate
     *
     * @throws SockudoException If $channel is invalid
     */
    private function validate_channel(string $channel): void
    {
        if (!preg_match('/\A#?[-a-zA-Z0-9_=@,.;]+\z/', $channel)) {
            throw new SockudoException('Invalid channel name ' . $channel);
        }
    }

    /**
     * Ensure a socket_id is valid based on our spec.
     *
     * @param string $socket_id The socket ID to validate
     *
     * @throws SockudoException If $socket_id is invalid
     */
    private function validate_socket_id(string $socket_id): void
    {
        if ($socket_id !== null && !preg_match('/\A\d+\.\d+\z/', $socket_id)) {
            throw new SockudoException('Invalid socket ID ' . $socket_id);
        }
    }

    /**
     * Ensure an user id is valid based on our spec.
     *
     * @param string $user_id The user id to validate
     *
     * @throws SockudoException If $user_id is invalid
     */
    private function validate_user_id(string $user_id): void
    {
        if ($user_id === null || empty($user_id)) {
            throw new SockudoException('Invalid user id ' . $user_id);
        }
    }

    /**
     * Utility function used to generate signing headers
     *
     * @param string $path
     * @param string $request_method
     * @param array $query_params [optional]
     *
     * @return array
     */
    private function sign(string $path, string $request_method = 'GET', array $query_params = []): array
    {
        return self::build_auth_query_params(
            $this->settings['auth_key'],
            $this->settings['secret'],
            $request_method,
            $path,
            $query_params
        );
    }

    /**
     * Build the Channels url prefix.
     *
     * @return string
     */
    private function channels_url_prefix(): string
    {
        return $this->settings['scheme'] . '://' . $this->settings['host'] . ':' . $this->settings['port'] . $this->settings['path'];
    }

    /**
     * Build the required HMAC'd auth string.
     *
     * @param string $auth_key
     * @param string $auth_secret
     * @param string $request_method
     * @param string $request_path
     * @param array $query_params [optional]
     * @param string $auth_version [optional]
     * @param string|null $auth_timestamp [optional]
     * @return array
     */
    public static function build_auth_query_params(
        string $auth_key,
        string $auth_secret,
        string $request_method,
        string $request_path,
        array $query_params = [],
        string $auth_version = '1.0',
        ?string $auth_timestamp = null
    ): array {
        $params = [];
        $params['auth_key'] = $auth_key;
        $params['auth_timestamp'] = (is_null($auth_timestamp) ? time() : $auth_timestamp);
        $params['auth_version'] = $auth_version;

        $params = array_merge($params, $query_params);
        ksort($params);

        $string_to_sign = "$request_method\n" . $request_path . "\n" . self::array_implode('=', '&', $params);

        $auth_signature = hash_hmac('sha256', $string_to_sign, $auth_secret, false);

        $params['auth_signature'] = $auth_signature;

        return $params;
    }

    /**
     * Implode an array with the key and value pair giving
     * a glue, a separator between pairs and the array
     * to implode.
     *
     * @param string       $glue      The glue between key and value
     * @param string       $separator Separator between pairs
     * @param array|string $array     The array to implode
     *
     * @return string The imploded array
     */
    public static function array_implode(string $glue, string $separator, $array): string
    {
        if (!is_array($array)) {
            return $array;
        }

        $string = [];
        foreach ($array as $key => $val) {
            if (is_array($val)) {
                $val = implode(',', $val);
            }
            $string[] = "{$key}{$glue}{$val}";
        }

        return implode($separator, $string);
    }

    /**
     * @deprecated in favour of of trigger and triggerAsync
     */
    public function make_request($channels, string $event, $data, array $params = [], bool $already_encoded = false): Request
    {
        if (is_string($channels) === true) {
            $channels = [$channels];
        }

        $this->validate_channels($channels);
        if (isset($params['socket_id'])) {
            $this->validate_socket_id($params['socket_id']);
        }

        $has_encrypted_channel = false;
        foreach ($channels as $chan) {
            if (SockudoCrypto::is_encrypted_channel($chan)) {
                $has_encrypted_channel = true;
                break;
            }
        }

        if ($has_encrypted_channel) {
            if (count($channels) > 1) {
                // For rationale, see limitations of end-to-end encryption in the README
                throw new SockudoException('You cannot trigger to multiple channels when using encrypted channels');
            } else {
                try {
                    $data_encoded = $this->crypto->encrypt_payload(
                        $channels[0],
                        $already_encoded ? $data : json_encode($data, JSON_THROW_ON_ERROR)
                    );
                } catch (\JsonException $e) {
                    throw new SockudoException('Data encoding error.');
                }
            }
        } else {
            try {
                $data_encoded = $already_encoded ? $data : json_encode($data, JSON_THROW_ON_ERROR);
            } catch (\JsonException $e) {
                throw new SockudoException('Data encoding error.');
            }
        }

        $query_params = [];

        $path = $this->settings['base_path'] . '/events';

        // json_encode might return false on failure
        if (!$data_encoded) {
            $this->log('Failed to perform json_encode on the the provided data: {error}', [
                'error' => print_r($data, true),
            ], LogLevel::ERROR);
        }

        $post_params = [];
        $post_params['name'] = $event;
        $post_params['data'] = $data_encoded;
        $post_params['channels'] = array_values($channels);

        $all_params = array_merge($post_params, $params);

        try {
            $post_value = json_encode($all_params, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new SockudoException('Data encoding error.');
        }

        $query_params['body_md5'] = md5($post_value);

        $signature = $this->sign($path, 'POST', $query_params);

        $this->log('trigger POST: {post_value}', compact('post_value'));

        $headers = [
            'Content-Type' => 'application/json',
            'X-Pusher-Library' => 'sockudo-http-php ' . self::$VERSION
        ];

        $params = array_merge($signature, $query_params);
        $query_string = self::array_implode('=', '&', $params);
        $full_path = ltrim($path, '/') . "?" . $query_string;
        return new Request('POST', $full_path, $headers, $post_value);
    }

    /**
     * Trigger an event by providing event name and payload.
     * Optionally provide a socket ID to exclude a client (most likely the sender).
     *
     * @param array|string $channels A channel name or an array of channel names to publish the event on.
     * @param string $event
     * @param mixed $data Event data
     * @param array $params [optional] Additional parameters. May include:
     *   - socket_id: string
     *   - info: string
     *   - extras: array{headers?: array<string,mixed>, ephemeral?: bool, idempotency_key?: string, echo?: bool}
     * @param bool $already_encoded [optional]
     *
     * @return object
     * @throws ApiErrorException Throws ApiErrorException if the Channels HTTP API responds with an error
     * @throws GuzzleException
     * @throws SockudoException Throws SockudoException if $channels is an array of size 101 or above or $socket_id is invalid
     */
    public function trigger($channels, string $event, $data, array $params = [], bool $already_encoded = false): object
    {
        $extra_headers = [];
        $idempotency_key = $this->resolveIdempotencyKey($params);
        if ($idempotency_key !== null) {
            $params['idempotency_key'] = $idempotency_key;
            $extra_headers['X-Idempotency-Key'] = $idempotency_key;
        }

        $post_value = $this->make_trigger_body($channels, $event, $data, $params, $already_encoded);
        $this->log('trigger POST: {post_value}', compact('post_value'));
        $result = $this->postWithRetry('/events', $post_value, [], $extra_headers);
        return $this->process_trigger_result($result);
    }

    /**
     * Asynchronously trigger an event by providing event name and payload.
     * Optionally provide a socket ID to exclude a client (most likely the sender).
     *
     * @param array|string $channels A channel name or an array of channel names to publish the event on.
     * @param string $event
     * @param mixed $data Event data
     * @param array $params [optional]
     * @param bool $already_encoded [optional]
     *
     * @return PromiseInterface
     * @throws SockudoException
     */
    public function triggerAsync($channels, string $event, $data, array $params = [], bool $already_encoded = false): PromiseInterface
    {
        $extra_headers = [];
        $idempotency_key = $this->resolveIdempotencyKey($params);
        if ($idempotency_key !== null) {
            $params['idempotency_key'] = $idempotency_key;
            $extra_headers['X-Idempotency-Key'] = $idempotency_key;
        }

        $post_value = $this->make_trigger_body($channels, $event, $data, $params, $already_encoded);
        $this->log('trigger POST: {post_value}', compact('post_value'));
        return $this->postAsync('/events', $post_value, [], $extra_headers)->then(function ($result) {
            return $this->process_trigger_result($result);
        });
    }

    /**
     * Send an event to a user.
     *
     * @param string $user_id
     * @param string $event
     * @param mixed $data Event data
     * @param bool $already_encoded [optional]
     *
     * @return object
     * @throws SockudoException
     */
    public function sendToUser(string $user_id, string $event, $data, bool $already_encoded = false): object
    {
        $this->validate_user_id($user_id);
        return $this->trigger(["#server-to-user-$user_id"], $event, $data, [], $already_encoded);
    }

    /**
     * Asynchronously send an event to a user.
     *
     * @param string $user_id
     * @param string $event
     * @param mixed $data Event data
     * @param bool $already_encoded [optional]
     *
     * @return PromiseInterface
     * @throws SockudoException
     */
    public function sendToUserAsync(string $user_id, string $event, $data, bool $already_encoded = false): PromiseInterface
    {
        $this->validate_user_id($user_id);
        return $this->triggerAsync(["#server-to-user-$user_id"], $event, $data, [], $already_encoded);
    }


    /**
     * @deprecated in favour of of trigger and triggerAsync
     */
    public function make_batch_request(array $batch = [], bool $already_encoded = false): Request
    {
        foreach ($batch as $key => $event) {
            $this->validate_channel($event['channel']);
            if (isset($event['socket_id'])) {
                $this->validate_socket_id($event['socket_id']);
            }

            $data = $event['data'];
            if (!is_string($data)) {
                try {
                    $data = $already_encoded ? $data : json_encode($data, JSON_THROW_ON_ERROR);
                } catch (\JsonException $e) {
                    throw new SockudoException('Data encoding error.');
                }
            }

            if (SockudoCrypto::is_encrypted_channel($event['channel'])) {
                $batch[$key]['data'] = $this->crypto->encrypt_payload($event['channel'], $data);
            } else {
                $batch[$key]['data'] = $data;
            }
        }

        $post_params = [];
        $post_params['batch'] = $batch;
        try {
            $post_value = json_encode($post_params, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new SockudoException('Data encoding error.');
        }

        $query_params = [];
        $query_params['body_md5'] = md5($post_value);
        $path = $this->settings['base_path'] . '/batch_events';

        $signature = $this->sign($path, 'POST', $query_params);

        $this->log('trigger POST: {post_value}', compact('post_value'));

        $headers = [
            'Content-Type' => 'application/json',
            'X-Pusher-Library' => 'sockudo-http-php ' . self::$VERSION
        ];

        $params = array_merge($signature, $query_params);
        $query_string = self::array_implode('=', '&', $params);
        $full_path = $path . "?" . $query_string;
        return new Request('POST', $full_path, $headers, $post_value);
    }

    /**
     * Trigger multiple events at the same time.
     *
     * @param array $batch [optional] An array of events to send
     * @param bool $already_encoded [optional]
     *
     * @return object
     * @throws ApiErrorException Throws ApiErrorException if the Channels HTTP API responds with an error
     * @throws GuzzleException
     * @throws SockudoException
     */
    public function triggerBatch(array $batch = [], bool $already_encoded = false): object
    {
        $post_value = $this->make_trigger_batch_body($batch, $already_encoded);
        $this->log('trigger POST: {post_value}', compact('post_value'));
        $result = $this->postWithRetry('/batch_events', $post_value);
        return $this->process_trigger_result($result);
    }

    /**
     * Asynchronously trigger multiple events at the same time.
     *
     * @param array $batch [optional] An array of events to send
     * @param bool $already_encoded [optional]
     *
     * @return PromiseInterface
     * @throws SockudoException
     */
    public function triggerBatchAsync(array $batch = [], bool $already_encoded = false): PromiseInterface
    {
        $post_value = $this->make_trigger_batch_body($batch, $already_encoded);
        $this->log('trigger POST: {post_value}', compact('post_value'));
        return $this->postAsync('/batch_events', $post_value)->then(function ($result) {
            return $this->process_trigger_result($result);
        });
    }

    /**
     * Terminates all connections established by the user with the given user id.
     *
     * @param string $user_id
     *
     * @throws SockudoException   If $user_id is invalid
     * @throws ApiErrorException Throws ApiErrorException if the Channels HTTP API responds with an error
     *
     * @return object response body
     *
     */
    public function terminateUserConnections(string $user_id): object
    {
        $this->validate_user_id($user_id);
        return $this->post("/users/$user_id/terminate_connections", "{}");
    }

    /**
     * Asynchronous request to terminates all connections established by the user with the given user id.
     *
     * @param string $user_id
     *
     * @throws SockudoException   If $userId is invalid
     *
     * @return PromiseInterface promise wrapping response body
     *
     */
    public function terminateUserConnectionsAsync(string $user_id): PromiseInterface
    {
        $this->validate_user_id($user_id);
        return $this->postAsync("/users/$user_id/terminate_connections", "{}");
    }


    /**
     * Fetch channel information for a specific channel.
     *
     * @param string $channel The name of the channel
     * @param array  $params  Additional parameters for the query e.g. $params = array( 'info' => 'connection_count' )
     *
     * @throws SockudoException   If $channel is invalid
     * @throws ApiErrorException Throws ApiErrorException if the Channels HTTP API responds with an error
     * @throws GuzzleException
     *
     */
    public function getChannelInfo(string $channel, array $params = []): object
    {
        $this->validate_channel($channel);

        return $this->get('/channels/' . $channel, $params);
    }

    /**
     * @deprecated in favour of getChannelInfo
     */
    public function get_channel_info(string $channel, array $params = []): object
    {
        return $this->getChannelInfo($channel, $params);
    }

    /**
     * Fetch a list containing all channels.
     *
     * @param array $params Additional parameters for the query e.g. $params = array( 'info' => 'connection_count' )
     *
     * @throws ApiErrorException Throws ApiErrorException if the Channels HTTP API responds with an error
     * @throws GuzzleException
     *
     */
    public function getChannels(array $params = []): object
    {
        $result = $this->get('/channels', $params);

        $result->channels = get_object_vars($result->channels);

        return $result;
    }

    /**
     * @deprecated in favour of getChannels
     */
    public function get_channels(array $params = []): object
    {
        return $this->getChannels($params);
    }

    /**
     * Fetch user ids currently subscribed to a presence channel.
     *
     * @param string $channel The name of the channel
     *
     * @throws ApiErrorException Throws ApiErrorException if the Channels HTTP API responds with an error
     * @throws GuzzleException
     *
     */
    public function getPresenceUsers(string $channel): object
    {
        return $this->get('/channels/' . $channel . '/users');
    }

    /**
     * Fetch durable history for a specific channel.
     *
     * @param string $channel The name of the channel
     * @param array  $params  History query params: limit, direction, cursor,
     *                        start_serial, end_serial, start_time_ms, end_time_ms
     *
     * @throws SockudoException
     * @throws ApiErrorException
     * @throws GuzzleException
     */
    public function getChannelHistory(string $channel, array $params = []): object
    {
        $this->validate_channel($channel);

        return $this->get('/channels/' . $channel . '/history', $params);
    }

    /**
     * @deprecated in favour of getChannelHistory
     */
    public function get_channel_history(string $channel, array $params = []): object
    {
        return $this->getChannelHistory($channel, $params);
    }

    /**
     * @deprecated in favour of getPresenceUsers
     */
    public function get_users_info(string $channel): object
    {
        return $this->getPresenceUsers($channel);
    }

    /**
     * GET arbitrary REST API resource using a synchronous http client.
     * All request signing is handled automatically.
     *
     * @param string $path        Path excluding /apps/APP_ID
     * @param array  $params      API params (see http://sockudo.com/docs/rest_api)
     * @param bool   $associative When true, return the response body as an associative array, else return as an object
     *
     * @throws ApiErrorException Throws ApiErrorException if the Channels HTTP API responds with an error
     * @throws GuzzleException
     * @throws SockudoException
     *
     * @return mixed See Sockudo API docs
     */
    public function get(string $path, array $params = [], $associative = false)
    {
        $path = $this->settings['base_path'] . $path;

        $signature = $this->sign($path, 'GET', $params);

        $headers = [
            'Content-Type' => 'application/json',
            'X-Pusher-Library' => 'sockudo-http-php ' . self::$VERSION
        ];

        $response = $this->client->get(ltrim($path, '/'), [
            'query' => $signature,
            'http_errors' => false,
            'headers' => $headers,
            'base_uri' => $this->channels_url_prefix(),
            'timeout' => $this->settings['timeout']
        ]);

        $status = $response->getStatusCode();

        if ($status !== 200) {
            $body = (string) $response->getBody();
            throw new ApiErrorException($body, $status);
        }

        try {
            $body = json_decode($response->getBody(), $associative, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new SockudoException('Data decoding error.');
        }

        return $body;
    }

    /**
     * POST arbitrary REST API resource using a synchronous http client.
     * All request signing is handled automatically.
     *
     * @param string $path        Path excluding /apps/APP_ID
     * @param mixed  $body        Request payload (see http://sockudo.com/docs/rest_api)
     * @param array  $params      API params (see http://sockudo.com/docs/rest_api)
     *
     * @throws ApiErrorException Throws ApiErrorException if the Channels HTTP API responds with an error
     * @throws GuzzleException
     * @throws SockudoException
     *
     * @return mixed Post response body
     */
    public function post(string $path, $body, array $params = [], array $extra_headers = [])
    {
        $path = $this->settings['base_path'] . $path;

        $params['body_md5'] = md5($body);

        $params_with_signature = $this->sign($path, 'POST', $params);

        $headers = array_merge([
            'Content-Type' => 'application/json',
            'X-Pusher-Library' => 'sockudo-http-php ' . self::$VERSION
        ], $extra_headers);

        try {
            $response = $this->client->post(ltrim($path, '/'), [
                'query' => $params_with_signature,
                'body' => $body,
                'http_errors' => false,
                'headers' => $headers,
                'base_uri' => $this->channels_url_prefix(),
                'timeout' => $this->settings['timeout']
            ]);
        } catch (ConnectException $e) {
            throw new ApiErrorException($e->getMessage());
        }

        $status = $response->getStatusCode();

        if ($status !== 200) {
            $body = (string) $response->getBody();
            throw new ApiErrorException($body, $status);
        }

        try {
            $response_body = json_decode($response->getBody(), false, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new SockudoException('Data decoding error.');
        }

        return $response_body;
    }

    /**
     * Asynchronously POST arbitrary REST API resource using a synchronous http client.
     * All request signing is handled automatically.
     *
     * @param string $path        Path excluding /apps/APP_ID
     * @param mixed  $body        Request payload (see http://sockudo.com/docs/rest_api)
     * @param array  $params      API params (see http://sockudo.com/docs/rest_api)
     *
     * @return PromiseInterface Promise wrapping POST response body
     */
    public function postAsync(string $path, $body, array $params = [], array $extra_headers = []): PromiseInterface
    {
        $path = $this->settings['base_path'] . $path;

        $params['body_md5'] = md5($body);

        $params_with_signature = $this->sign($path, 'POST', $params);

        $headers = array_merge([
            'Content-Type' => 'application/json',
            'X-Pusher-Library' => 'sockudo-http-php ' . self::$VERSION
        ], $extra_headers);

        return $this->client->postAsync(ltrim($path, '/'), [
            'query' => $params_with_signature,
            'body' => $body,
            'http_errors' => false,
            'headers' => $headers,
            'base_uri' => $this->channels_url_prefix(),
            'timeout' => $this->settings['timeout'],
        ])->then(function ($response) {
            $status = $response->getStatusCode();

            if ($status !== 200) {
                $body = (string) $response->getBody();
                throw new ApiErrorException($body, $status);
            }

            try {
                $response_body = json_decode($response->getBody(), false, 512, JSON_THROW_ON_ERROR);
            } catch (\JsonException $e) {
                throw new SockudoException('Data decoding error.');
            }

            return $response_body;
        }, function (ConnectException $e) {
            throw new ApiErrorException($e->getMessage());
        });
    }

    /**
     * Creates a user authentication signature.
     *
     * @param string $socket_id
     * @param array $user_data
     *
     * @return string Json encoded authentication string.
     * @throws SockudoException Throws exception if $channel is invalid or above or $socket_id is invalid
     */
    public function authenticateUser(string $socket_id, array $user_data): string
    {
        $this->validate_socket_id($socket_id);
        $this->validate_user_data($user_data);
        $serialized_user_data = json_encode($user_data, JSON_THROW_ON_ERROR);
        $signature = hash_hmac('sha256', "$socket_id::user::$serialized_user_data", $this->settings['secret'], false);
        $auth = $this->settings['auth_key'] . ':' . $signature;

        return json_encode(
            ['auth' => $auth, 'user_data' => $serialized_user_data],
            JSON_THROW_ON_ERROR
        );
    }

    /**
     * Creates a channel authorization signature.
     *
     * @param string $channel
     * @param string $socket_id
     * @param string|null $custom_data
     *
     * @return string Json encoded authentication string.
     * @throws SockudoException Throws exception if $channel is invalid or above or $socket_id is invalid
     */
    public function authorizeChannel(string $channel, string $socket_id, ?string $custom_data = null): string
    {
        $this->validate_channel($channel);
        $this->validate_socket_id($socket_id);

        if ($custom_data) {
            $signature = hash_hmac('sha256', $socket_id . ':' . $channel . ':' . $custom_data, $this->settings['secret'], false);
        } else {
            $signature = hash_hmac('sha256', $socket_id . ':' . $channel, $this->settings['secret'], false);
        }

        $signature = ['auth' => $this->settings['auth_key'] . ':' . $signature];
        // add the custom data if it has been supplied
        if ($custom_data) {
            $signature['channel_data'] = $custom_data;
        }

        if (SockudoCrypto::is_encrypted_channel($channel)) {
            if (!is_null($this->crypto)) {
                $signature['shared_secret'] = base64_encode($this->crypto->generate_shared_secret($channel));
            } else {
                throw new SockudoException('You must specify an encryption master key to authorize an encrypted channel');
            }
        }

        try {
            $response = json_encode($signature, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        } catch (\JsonException $e) {
            throw new SockudoException('Data encoding error.');
        }

        return $response;
    }

    /**
     * Convenience function for presence channel authorization.
     *
     * Equivalent to authorizeChannel($channel, $socket_id, json_encode(['user_id' => $user_id, 'user_info' => $user_info], JSON_THROW_ON_ERROR))
     *
     * @param string $channel
     * @param string $socket_id
     * @param string $user_id
     * @param mixed $user_info
     *
     * @return string
     * @throws SockudoException Throws exception if $channel is invalid or above or $socket_id is invalid
     */
    public function authorizePresenceChannel(string $channel, string $socket_id, string $user_id, $user_info = null): string
    {
        $user_data = ['user_id' => $user_id];
        if ($user_info) {
            $user_data['user_info'] = $user_info;
        }

        try {
            return $this->authorizeChannel($channel, $socket_id, json_encode($user_data, JSON_THROW_ON_ERROR));
        } catch (\JsonException $e) {
            throw new SockudoException('Data encoding error.');
        }
    }


    /**
     * @deprecated in favour of authorizeChannel
     */
    public function socketAuth(string $channel, string $socket_id, ?string $custom_data = null): string
    {
        return $this->authorizeChannel($channel, $socket_id, $custom_data);
    }

    /**
     * @deprecated in favour of authorizeChannel
     */
    public function socket_auth(string $channel, string $socket_id, ?string $custom_data = null): string
    {
        return $this->authorizeChannel($channel, $socket_id, $custom_data);
    }

    /**
     * @deprecated in favour of authorizePresenceChannel
     */
    public function presenceAuth(string $channel, string $socket_id, string $user_id, $user_info = null): string
    {
        return $this->authorizePresenceChannel($channel, $socket_id, $user_id, $user_info);
    }

    /**
     * @deprecated in favour of authorizePresenceChannel
     */
    public function presence_auth(string $channel, string $socket_id, string $user_id, $user_info = null): string
    {
        return $this->authorizePresenceChannel($channel, $socket_id, $user_id, $user_info);
    }

    /**
     * Verify that a webhook actually came from Sockudo, decrypts any encrypted events, and marshals them into a PHP object.
     *
     * @param array  $headers a array of headers from the request (for example, from getallheaders())
     * @param string $body    the body of the request (for example, from file_get_contents('php://input'))
     *
     * @throws SockudoException
     *
     * @return Webhook marshalled object with the properties time_ms (an int) and events (an array of event objects)
     */
    public function webhook(array $headers, string $body): object
    {
        $this->verifySignature($headers, $body);

        $decoded_events = [];
        try {
            $decoded_json = json_decode($body, false, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            $this->log('Unable to decrypt webhook event payload.', null, LogLevel::WARNING);
            throw new SockudoException('Data encoding error.');
        }

        foreach ($decoded_json->events as $event) {
            if (SockudoCrypto::is_encrypted_channel($event->channel)) {
                if (!is_null($this->crypto)) {
                    $decryptedEvent = $this->crypto->decrypt_event($event);

                    if ($decryptedEvent === false) {
                        $this->log('Unable to decrypt webhook event payload. Wrong key? Ignoring.', null, LogLevel::WARNING);
                        continue;
                    }
                    $decoded_events[] = $decryptedEvent;
                } else {
                    $this->log('Got an encrypted webhook event payload, but no master key specified. Ignoring.', null, LogLevel::WARNING);
                }
            } else {
                $decoded_events[] = $event;
            }
        }
        return new Webhook($decoded_json->time_ms, $decoded_events);
    }

    /**
     * Verify that a given Sockudo Signature is valid.
     *
     * @param array  $headers an array of headers from the request (for example, from getallheaders())
     * @param string $body    the body of the request (for example, from file_get_contents('php://input'))
     *
     * @throws SockudoException if signature is incorrect.
     */
    public function verifySignature(array $headers, string $body): void
    {
        $x_pusher_key = $headers['X-Pusher-Key'];
        $x_pusher_signature = $headers['X-Pusher-Signature'];
        if ($x_pusher_key === $this->settings['auth_key']) {
            $expected = hash_hmac('sha256', $body, $this->settings['secret']);
            if ($expected === $x_pusher_signature) {
                return;
            }
        }

        throw new SockudoException(sprintf('Received WebHook with invalid signature: got %s.', $x_pusher_signature));
    }

    /**
     * @deprecated in favour of verifySignature
     */
    public function ensure_valid_signature(array $headers, string $body): void
    {
        $this->verifySignature($headers, $body);
    }

    /**
     * Returns an event represented by an associative array to be used in creating events and batch_events requests
     *
     * @param array|string $channels A channel name or an array of channel names to publish the event on.
     * @param string $event
     * @param mixed $data Event data
     * @param array $params [optional]
     * @param bool $already_encoded [optional]
     *
     * @throws SockudoException
     *
     * @return array Event associative array
     */
    private function make_event(array $channels, string $event, $data, array $params = [], ?string $info = null, bool $already_encoded = false): array
    {
        $has_encrypted_channel = false;
        foreach ($channels as $chan) {
            if (SockudoCrypto::is_encrypted_channel($chan)) {
                $has_encrypted_channel = true;
                break;
            }
        }

        if ($has_encrypted_channel) {
            if (SockudoCrypto::has_mixed_channels($channels)) {
                throw new SockudoException('You cannot trigger to encrypted and non-encrypted channels at the same time');
            } else {
                try {
                    $data_encoded = $this->crypto->encrypt_payload(
                        $channels[0],
                        $already_encoded ? $data : json_encode($data, JSON_THROW_ON_ERROR)
                    );
                } catch (\JsonException $e) {
                    throw new SockudoException('Data encoding error.');
                }
            }
        } else {
            try {
                $data_encoded = $already_encoded ? $data : json_encode($data, JSON_THROW_ON_ERROR);
            } catch (\JsonException $e) {
                throw new SockudoException('Data encoding error.');
            }
        }

        // json_encode might return false on failure
        if (!$data_encoded) {
            $this->log('Failed to perform json_encode on the the provided data: {error}', [
                'error' => print_r($data, true),
            ], LogLevel::ERROR);
        }

        $post_params = [];
        $post_params['name'] = $event;
        $post_params['data'] = $data_encoded;
        $channel_values = array_values($channels);
        if (count($channel_values) == 1) {
            $post_params['channel'] = $channel_values[0];
        } else {
            $post_params['channels'] = $channel_values;
        }
        if (!is_null($info)) {
            $post_params['info'] = $info;
        }

        return array_merge($post_params, $params);
    }

    /**
     * Returns the body of a trigger events request serialized as string ready to be sent in a request
     *
     * @param array|string $channels A channel name or an array of channel names to publish the event on.
     * @param string $event
     * @param mixed $data Event data
     * @param array $params [optional]
     * @param bool $already_encoded [optional]
     *
     * @throws SockudoException
     *
     * @return string
     */
    private function make_trigger_body($channels, string $event, $data, array $params = [], bool $already_encoded = false): string
    {
        if (is_string($channels) === true) {
            $channels = [$channels];
        }

        $this->validate_channels($channels);
        if (isset($params['socket_id'])) {
            $this->validate_socket_id($params['socket_id']);
        }

        try {
            return json_encode(
                $this->make_event($channels, $event, $data, $params, null, $already_encoded),
                JSON_THROW_ON_ERROR
            );
        } catch (\JsonException $e) {
            throw new SockudoException('Data encoding error.');
        }
    }

    /**
     * Returns the body of a trigger batch events request serialized as string ready to be sent in a request
     *
     * @param array|string $channels A channel name or an array of channel names to publish the event on.
     * @param string $event
     * @param mixed $data Event data
     * @param array $params [optional]
     * @param bool $already_encoded [optional]
     *
     * @throws SockudoException
     *
     * @return string
     */
    private function make_trigger_batch_body(array $batch = [], bool $already_encoded = false): string
    {
        $autoIdem = $this->settings['auto_idempotency_key'] ?? false;
        $serial = null;
        if ($autoIdem) {
            $serial = ++$this->publishSerial;
        }

        foreach ($batch as $key => $event) {
            $this->validate_channel($event['channel']);
            $params = [];
            if (isset($event['socket_id'])) {
                $this->validate_socket_id($event['socket_id']);
                $params['socket_id'] = $event['socket_id'];
            }

            $idempotency_key = null;
            if (isset($event['idempotency_key'])) {
                $idempotency_key = $event['idempotency_key'] === true
                    ? self::generateIdempotencyKey()
                    : $event['idempotency_key'];
                $params['idempotency_key'] = $idempotency_key;
            } elseif ($autoIdem) {
                $idempotency_key = "{$this->baseId}:{$serial}:{$key}";
                $params['idempotency_key'] = $idempotency_key;
            }

            if (isset($event['extras'])) {
                $params['extras'] = $event['extras'];
            }

            $batch[$key] = $this->make_event([$event['channel']], $event['name'], $event['data'], $params, $event['info'] ?? null, $already_encoded);
        }

        try {
            return json_encode(['batch' => $batch], JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new SockudoException('Data encoding error.');
        }
    }

    /**
     * Mutates the result of a trigger (batch) request to replace channel names with channel objects
     *
     * @param object $result result of the trigger (batch) request
     *
     * @return object
     */
    private function process_trigger_result(object $result): object
    {
        if (property_exists($result, 'channels') && is_object($result->channels)) {
            $result->channels = get_object_vars($result->channels);
        }

        return $result;
    }

    /**
     * Generate a random idempotency key (base64url-encoded 12 random bytes).
     *
     * @return string 16-character base64url string
     */
    public static function generateIdempotencyKey(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(12)), '+/', '-_'), '=');
    }

    /**
     * Resolve the idempotency key from params. If the value is boolean true,
     * auto-generate a UUID v4. If it is a string, use it directly.
     * Removes the key from params by reference if present.
     *
     * @param array &$params
     * @return string|null
     */
    private function resolveIdempotencyKey(array &$params): ?string
    {
        if (isset($params['idempotency_key'])) {
            $value = $params['idempotency_key'];
            unset($params['idempotency_key']);

            if ($value === true) {
                return self::generateIdempotencyKey();
            }

            return (string) $value;
        }

        if ($this->settings['auto_idempotency_key'] ?? false) {
            $serial = ++$this->publishSerial;
            return "{$this->baseId}:{$serial}";
        }

        return null;
    }

    /**
     * POST with built-in retry for network errors and 5xx responses.
     * Reuses the same request (and idempotency key) across attempts.
     *
     * @param string $path
     * @param string $body
     * @param array $params
     * @param array $extra_headers
     * @return object
     * @throws ApiErrorException
     * @throws GuzzleException
     * @throws SockudoException
     */
    private function postWithRetry(string $path, string $body, array $params = [], array $extra_headers = []): object
    {
        $lastException = null;
        for ($attempt = 1; $attempt <= $this->maxRetries; $attempt++) {
            try {
                return $this->post($path, $body, $params, $extra_headers);
            } catch (ApiErrorException $e) {
                $status = $e->getCode();
                if ($status >= 500 && $status < 600 && $attempt < $this->maxRetries) {
                    $lastException = $e;
                    continue;
                }
                throw $e;
            } catch (ConnectException $e) {
                if ($attempt < $this->maxRetries) {
                    $lastException = $e;
                    continue;
                }
                throw new ApiErrorException($e->getMessage());
            }
        }
        throw $lastException;
    }

    private function validate_user_data(array $user_data): void
    {
        if (is_null($user_data)) {
            throw new SockudoException('user_data is null');
        }
        if (!array_key_exists('id', $user_data)) {
            throw new SockudoException('user_data has no id field');
        }
        $this->validate_user_id($user_data['id']);
    }
}
