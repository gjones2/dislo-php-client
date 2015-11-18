<?php

namespace Ixolit\DisloApiClient;

/**
 * This class is the abstract query handler for raw HTTP queries.
 */
class HTTPQueryHandler {
	/**
	 * @var string
	 */
	protected $endpoint;

	/**
	 * @var string
	 */
	protected $apiKey;

	/**
	 * @var string
	 */
	protected $apiSecret;

	/**
	 * @var string[]
	 */
	private $headers = array();

	/**
	 * Initialize the QueryHandler with authentication information.
	 *
	 * @param string $endpoint
	 * @param string $apiKey
	 * @param string $apiSecret
	 */
	public function __construct($endpoint, $apiKey, $apiSecret) {
		$this->endpoint  = $endpoint;
		$this->apiKey    = $apiKey;
		$this->apiSecret = $apiSecret;
	}

	/**
	 * Perform the raw API call with signing.
	 *
	 * @param string $uri
	 * @param array  $parameters
	 *
	 * @return string
	 * @throws \Exception
	 */
	public function call($uri, $parameters = array()) {
		$time = new \DateTime();
		$url = explode('/', $this->endpoint . $uri, 4);
		$body = json_encode($parameters);
		$uri =  '/' . $url[3];
		$uri .= '?timestamp=' . $time->format('U');
		$uri .= '&api_key=' . $this->apiKey;
		$uri .= '&signature_algorithm=sha512';
		$signature = hash_hmac('sha512', $uri . $body, $this->apiSecret);
		$uri .= '&signature=' . $signature;

		$headers = array(
			'Content-Type: application/json',
            'Content-Length: ' . strlen($body)
		);

		$conn = curl_init();

		curl_setopt($conn, CURLOPT_URL, $this->endpoint . $uri);
		curl_setopt($conn, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($conn, CURLOPT_HEADER, 1);
		curl_setopt($conn, CURLOPT_POST, 1);
		curl_setopt($conn, CURLOPT_HTTPHEADER, $headers);
		curl_setopt($conn, CURLOPT_POSTFIELDS, $body);

		$response = curl_exec($conn);
		list($headers, $body) = explode("\r\n\r\n", $response, 2);
		$this->setHeaders($headers);

		curl_close($conn);

		$signatureAlgorithm = $this->getHeader('X-Signature-Algorithm');

		if($signatureAlgorithm !== 'sha512') {
			throw new \Exception('Response signature algorithm "' . $signatureAlgorithm . '" does not match request algorithm!');
		}

		$timestamp = (int) $this->getHeader('X-Signature-Timestamp');
		$signature = $this->getHeader('X-Signature');
		$expectedSignature = hash_hmac('sha512', $body . "\n\n" . $timestamp . "\n" . $signatureAlgorithm, $this->apiSecret);

		if($expectedSignature !== $signature) {
			throw new \Exception('Response signature '. $signature .' does not match expected signature '. $expectedSignature);
		}

		$lowestTimeBound = time() - 300;
		$highestTimeBound = $lowestTimeBound + 600;

		if($timestamp < $lowestTimeBound || $timestamp > $highestTimeBound) {
			throw new \Exception('Response timestamp is out of bounds: '. $timestamp .'. Expected '. $lowestTimeBound .' to '. $highestTimeBound);
		}

		return $body;
	}

	/**
	 * @param string $headerName
	 *
	 * @return string
	 */
	private function getHeader($headerName) {
		return array_key_exists($headerName, $this->headers) ? $this->headers[$headerName] : '';
	}

	/**
	 * @param string $headers
	 * @return void
	 */
	private function setHeaders($headers) {
		$this->headers = array();
		$headers = explode("\n", $headers);

		foreach($headers as $header) {
			if(!preg_match('/[^:]+:.*/', $header)) {
				continue;
			}

			$headerParts = explode(':', $header, 2);
			$this->headers[$headerParts[0]] = trim($headerParts[1]);
		}
	}

	/**
	 * @param string $data
	 *
	 * @return array
	 */
	private function parseCsv($data) {
		$delimiter = ',';
		$result = array();
		$data = explode("\n", $data);

		foreach($data as $row) {
			if(empty($row)) {
				continue;
			}

			preg_match_all("/([^\"'". $delimiter ."]+|[\"'][^\"']+[\"'])". $delimiter ."?/", $row, $splitRow);

			$result[] = array_map(function($col) {
				return trim($col, " \t\n\r\0\x0B\"");
			}, $splitRow[1]);
		}

		return $result;
	}

	/**
	 * @param string $data
	 *
	 * @return array
	 */
	private function parseCsvHeader($data) {
		$data = $this->parseCsv($data);
		$headers = array_shift($data);
		$result = array();

		foreach($data as $row) {
			$newRow = array();

			foreach($row as $columnIndex => $columnValue) {
				$newRow[$headers[$columnIndex]] = $columnValue;
			}

			$result[] = $newRow;
		}

		return $result;
	}

	/**
	 * Run a custom report by ID. Only works on expert-mode queries, results for simple
	 * editor queries are undefined due to how parameters are handled.
	 *
	 * @param string $reportId
	 * @param array  $parameters
	 * @param int    $limit
	 * @param int    $offset
	 * @param array  $order
	 *
	 * @throws \Exception
	 *
	 * @return array
	 */
	public function customReport($reportId, $parameters = array(), $limit = null, $offset = null, $order = array()) {
		$response = $this->call('/export/v2/report/' . $reportId, array(
			'parameters' => $parameters,
			'limit'      => $limit,
			'offset'     => $offset,
			'order'      => $order
		));

		return $this->parseCsvHeader($response);
	}

	/**
	 * Run a custom report by explicitly specifying the SQL query to run, much like in
	 * the web interface. Parameters are optional, but recommended if unsafe data must
	 * be inserted into SQL queries.
	 *
	 * @param string $sql
	 * @param array  $parameters
	 * @param int    $limit
	 * @param int    $offset
	 * @param array  $order
	 *
	 * @return array
	 */
	public function customQuery($sql, $parameters = array(), $limit = null, $offset = null, $order = array()) {
		$response = $this->call('/export/v2/query', array(
			'query'      => $sql,
			'parameters' => $parameters,
			'limit'      => $limit,
			'offset'     => $offset,
			'order'      => $order
		));

		return $this->parseCsvHeader($response);
	}
}