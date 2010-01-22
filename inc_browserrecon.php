<?php
/*
+--------------------------------------------------------------------+
|    browserrecon 1.4-php
|
|    (c) 2008 by Marc Ruef
|    marc.ruef@computec.ch
|    http://www.computec.ch/projekte/browserrecon/
|
|    Released under the terms and conditions of the
|    GNU General Public License 3.0 (http://gnu.org).
|
|    Installation:
|    Extract the archive in a folder accessible by your
|    web browser. Include the browserrecon script with
|    the following function call:
|        include ('browserrecon/inc_browserrecon.php');
|
|    Use:
|    Use the function browserrecon() to do a web browser
|    fingerprinting with the included utility. The first
|    argument of the function call is the raw http headers
|    sent by the client. You might use the following
|    call to do a live fingerprinting of visiting users:
|        echo browserrecon(getfullheaders());
|
|    It is also possible to get the data from another
|    source. For example a local file named header.txt:
|        echo browserrecon(file_get_contents('header.txt')));
|
|    Or the data sent via a http post form:
|        echo browserrecon($_POST['header']);
|
|    Reporting:
|    You are able to change the behavior of the reports
|    sent back by browserrecon(). As second argument you
|    might use the following parameters:
|        - simple: Identified implementation only
|        - besthitdetail: Additional hit detail
|        - list: Unordered list of all matches
|        - besthitlist: Top ten list of the best matches
|
+--------------------------------------------------------------------+
*/

/**
 * Identify a browser
 *
 * @param   string  $rawHeader  The headers, as returned by getFullHeaders()
 *
 * @return
 */
function browserRecon($rawHeader, $mode='besthit', $database='') {
    $globalFingerprint = identifyGlobalFingerprint($database, $rawHeader);
    $possibilities = countHitPossibilities($rawHeader);
    $matchStatistics = generateMatchStatistics($globalFingerprint, $mode, $possibilities);

    return announceFingerprintMatches($matchStatistics);
}

/**
 * Get all of the headers as a string:
 *      User-Agent: Foobar
 *      Referer:    http://google.com
 *
 * @return  string  The headers as colon separated key-value pairs, one per line
 */
function getFullHeaders() {
    $headers = getallheaders();

    // Join the headers into a single string
    foreach($headers as $header => $value) {
        $full_header .= $header .': '. $value ."\n";
    }

    return $full_header;
}

/**
 * Get a header value from the raw headers.
 *
 * @param   string  $rawHeader  The headers, as returned by getFullHeaders()
 * @param   string  $headerName The desired header's name
 *
 * @return  string  The give header's value
 */
function getHeaderValue ($rawHeader, $headerName) {
    $headers = explode ("\n", $rawHeader, 64);
    $headerNameSmall = strtolower($headerName);

    // Return the header value
    foreach($headers as $header) {
        list($key, $value) = explode (':', $header, 2);
        if (strtolower($key) == $headerNameSmall) {
            return trim($value);
        }
    }
}

/**
 * Get a comma-separated list of header keys.
 *
 * @param   string  $rawHeader  The headers, as returned by getFullHeaders()
 *
 * @return  string  The header keys as a comma-separated list
 */
function getHeaderOrder($rawHeader) {
    $headers = explode ("\n", $rawHeader, 64);
    $headers_count = count($headers);

    for($i=0; $i<$headers_count; ++$i) {
        list($key, $value) = explode (':', $header, 2);

        if (strlen($key) > 2) {
            $header_order .= trim($key);

            // If there is another header next, add a comma & space
            if (strlen($headers[$i+1]) > 0) {
                $header_order .= ', ';
            }
        }
    }

    return $header_order;
}

/**
 * Get the maximum number of hits that this browser can get, based upon the
 * number of headers that it provided which we know about.
 *
 * @param   string  $rawHeader  The headers, as returned by getFullHeaders()
 *
 * @return  integer The count of hit possibilities
 */
function countHitPossibilities($rawHeader) {
    (getHeaderValue ($rawHeader, 'User-Agent') != '' ? ++$count : '');
    (getHeaderValue ($rawHeader, 'Accept') != '' ? ++$count : '');
    (getHeaderValue ($rawHeader, 'Accept-Language') != '' ? ++$count : '');
    (getHeaderValue ($rawHeader, 'Accept-Encoding') != '' ? ++$count : '');
    (getHeaderValue ($rawHeader, 'Accept-Charset') != '' ? ++$count : '');
    (getHeaderValue ($rawHeader, 'Keep-Alive') != '' ? ++$count : '');
    (getHeaderValue ($rawHeader, 'Connection') != '' ? ++$count : '');
    (getHeaderValue ($rawHeader, 'Cache-Control') != '' ? ++$count : '');
    (getHeaderValue ($rawHeader, 'UA-Pixels') != '' ? ++$count : '');
    (getHeaderValue ($rawHeader, 'UA-Color') != '' ? ++$count : '');
    (getHeaderValue ($rawHeader, 'UA-OS') != '' ? ++$count : '');
    (getHeaderValue ($rawHeader, 'UA-CPU') != '' ? ++$count : '');
    (getHeaderValue ($rawHeader, 'TE') != '' ? ++$count : '');
    (getHeaderOrder($rawHeader) != '' ? ++$count : '');

    return $count;
}

/**
 * Find each of the headers we care about in the databases.
 *
 * @param   string  $database   The database file prefix to use
 * @param   string  $rawHeader  The headers, as returned by getFullHeaders()
 *
 * @return  string  Semicolon separated list of browsers that match
 */
function identifyGlobalFingerprint($database, $rawHeader) {
    $matchList = findMatchInDatabase ($database.'user-agent.fdb', getHeaderValue($rawHeader, 'User-Agent'));
    $matchList .= findMatchInDatabase ($database.'accept.fdb', getHeaderValue($rawHeader, 'Accept'));
    $matchList .= findMatchInDatabase ($database.'accept-language.fdb', getHeaderValue($rawHeader, 'Accept-Language'));
    $matchList .= findMatchInDatabase ($database.'accept-encoding.fdb', getHeaderValue($rawHeader, 'Accept-Encoding'));
    $matchList .= findMatchInDatabase ($database.'accept-charset.fdb', getHeaderValue($rawHeader, 'Accept-Charset'));
    $matchList .= findMatchInDatabase ($database.'keep-alive.fdb', getHeaderValue($rawHeader, 'Keep-Alive'));
    $matchList .= findMatchInDatabase ($database.'connection.fdb', getHeaderValue($rawHeader, 'Connection'));
    $matchList .= findMatchInDatabase ($database.'cache-control.fdb', getHeaderValue($rawHeader, 'Cache-Control'));
    $matchList .= findMatchInDatabase ($database.'ua-pixels.fdb', getHeaderValue($rawHeader, 'UA-Pixels'));
    $matchList .= findMatchInDatabase ($database.'ua-color.fdb', getHeaderValue($rawHeader, 'UA-Color'));
    $matchList .= findMatchInDatabase ($database.'ua-os.fdb', getHeaderValue($rawHeader, 'UA-OS'));
    $matchList .= findMatchInDatabase ($database.'ua-cpu.fdb', getHeaderValue($rawHeader, 'UA-CPU'));
    $matchList .= findMatchInDatabase ($database.'te.fdb', getHeaderValue($rawHeader, 'TE'));
    $matchList .= findMatchInDatabase ($database.'header-order.fdb', getHeaderOrder($rawHeader));

    return $matchList;
}

/**
 * Get a list of browsers that match the given header.
 *
 * @param   string  $databaseFile   The DB file to read headers from
 * @param   string  $headerValue    The header from the browser
 *
 * @return  string  Semicolon separated list of browsers that match
 */
function findMatchInDatabase ($databaseFile, $headerValue) {
    // Get the whole database as an array of lines
    $database = file($databaseFile);

    foreach($database as $entry) {
        // Lines are "Browser name;header value"
        list($dbBrowser, $dbValue) = explode(';', $entry, 2);

        if ($headerValue == rtrim($dbValue)) {
            // Append this browser name to the matches
            $matches .= $dbBrowser .';';
        }
    }

    return $matches;
}

/**
 * @param   string  $matchList  Semicolon separated list of browsers that match
 *
 * @return  string  Lines with the name of a browser & the number of header matches
 */
function generateMatchStatistics($matchList) {
    $matchesArray = explode(';', $matchList);
    $matches = array_unique($matchesArray);

    foreach($matches as $match) {
        $matchStatistic .= $match .'='. countif($matchesArray, $match) ."\n";
    }

    return $matchStatistic;
}

/**
 * Count the number of times $search occurs in $input.
 *
 * @param   array   $input  The array to search
 * @param   string  $search The string to search for
 *
 * @return  integer The number of times $search was found in $input
 */
function countif($input, $search) {
    foreach($input as $entry) {
        if ($entry == $search) {
            ++$sum;
        }
    }

    return $sum;
}

/**
 * @param   string  $fullMatchList      Match statistics from generateMatchStatistics()
 * @param   string  $mode               Matching mode
 * @param   string  $hitPossibilities
 *
 * @return
 */
function announceFingerprintMatches($fullMatchList, $mode='besthit', $hitPossibilities=0) {
    // Break up into individual match lines
    $headers = explode ("\n", $fullMatchList);

    foreach($headers as $header) {
        // Break line into matchName & matchCount
        list($matchName, $matchCount) = explode ('=', $header, 2);

        // If the matchNameisn't empty
        if (strlen($matchName)) {
            // Store $matchName & $matchCount if this is the best so far
            if ($bestHitCount < $matchCount) {
                $bestHitName = $matchName;
                $bestHitCount = $matchCount;
            }

            // Store them all in the list of matches
            $resultList .= $matchName.': '. $matchCount."\n";
            $resultArray[] = $matchCount.';'. htmlspecialchars($matchName);
        }
    }

    if ($mode == 'list') {
        return $resultList;
    } elseif ($mode == 'besthitlist') {
        rsort($resultArray);

        for ($i = 0; $i < 10; ++$i) {
            $scan_resultitem = explode (';', $resultArray[$i], 2);
            if ($scan_resultitem['0'] > 0) {
                if ($hitPossibilities > 0) {
                    $scan_hitaccuracy = round((100 / $hitPossibilities) * $scan_resultitem['0'], 2);
                } else {
                    $scan_hitaccuracy = round((100 / $bestHitCount) * $scan_resultitem['0'], 2);
                }

                $hitList .= ($i+1).'. '.$scan_resultitem['1'].' ('.$scan_hitaccuracy. '% with '.$scan_resultitem['0'].' hits)';

                if ($i<9) {
                    $hitList .= "\n";
                }
            }
        }

        return $hitList;
    } elseif ($mode == 'besthitdetail') {
        if ($hitPossibilities > 0) {
            $scan_hitaccuracy = round((100 / $hitPossibilities) * $bestHitCount, 2);
        } else {
            $scan_hitaccuracy = 100;
        }

        return $bestHitName.' ('.$scan_hitaccuracy. '% with '.$bestHitCount.' hits)';
    } else {
        return $bestHitName;
    }
}

//////////////  ONLY USED FOR ADDING FINGERPRINTS  ////////////////
function addToDatabase ($databaseFile, $implementation, $value) {
    if (strlen($implementation) && strlen($value)) {
        if (!isindatabase($databaseFile, $implementation, $value)) {
            if (is_writable($databaseFile)) {
                if ($fh = fopen($databaseFile, 'a')) {
                    fwrite ($fh, $implementation.';'.$value."\n");
                    fclose ($fh);
                }
            }
        }
    }
}

function isInDatabase ($databaseFile, $implementation, $value) {
    $database = file ($databaseFile);

    foreach($database as $entry) {
        if ($implementation.';'.$value == rtrim($entry)) {
            return 1;
        }
    }

    return 0;
}

// Save Fingerprints
function sendFingerprint($implementation, $fingerprint, $details='') {
    $mailmessage = 'Implementation: '.$implementation."\n\n";
    if ($details) {
        $mailmessage.= $details."\n\n";
    }
    $mailmessage.= $fingerprint."\n";
    mail('marc.ruef@computec.ch', '[browserrecon] fingerprint upload', $mailmessage);
}

function saveAllFingerprintsToDatabase ($rawHeader, $implementation) {
    saveNewFingerprintToDatabase ('scan/user-agent.fdb', $implementation, getHeaderValue($rawHeader, 'User-Agent'));
    saveNewFingerprintToDatabase ('scan/accept.fdb', $implementation, getHeaderValue($rawHeader, 'Accept'));
    saveNewFingerprintToDatabase ('scan/accept-language.fdb', $implementation, getHeaderValue($rawHeader, 'Accept-Language'));
    saveNewFingerprintToDatabase ('scan/accept-encoding.fdb', $implementation, getHeaderValue($rawHeader, 'Accept-Encoding'));
    saveNewFingerprintToDatabase ('scan/accept-charset.fdb', $implementation, getHeaderValue($rawHeader, 'Accept-Charset'));
    saveNewFingerprintToDatabase ('scan/keep-alive.fdb', $implementation, getHeaderValue($rawHeader, 'Keep-Alive'));
    saveNewFingerprintToDatabase ('scan/connection.fdb', $implementation, getHeaderValue($rawHeader, 'Connection'));
    saveNewFingerprintToDatabase ('scan/cache-control.fdb', $implementation, getHeaderValue($rawHeader, 'Cache-Control'));
    saveNewFingerprintToDatabase ('scan/ua-pixels.fdb', $implementation, getHeaderValue($rawHeader, 'UA-Pixels'));
    saveNewFingerprintToDatabase ('scan/ua-color.fdb', $implementation, getHeaderValue($rawHeader, 'UA-Color'));
    saveNewFingerprintToDatabase ('scan/ua-os.fdb', $implementation, getHeaderValue($rawHeader, 'UA-OS'));
    saveNewFingerprintToDatabase ('scan/ua-cpu.fdb', $implementation, getHeaderValue($rawHeader, 'UA-CPU'));
    saveNewFingerprintToDatabase ('scan/te.fdb', $implementation, getHeaderValue($rawHeader, 'TE'));
    saveNewFingerprintToDatabase ('scan/header-order.fdb', $implementation, getHeaderOrder($rawHeader));
}

function saveNewFingerprintToDatabase ($filename, $implementation, $value) {
    addToDatabase ($filename, $implementation, $value);
}

// Additional Analysis Modules
function usedproxy($request) {
    if (strpos($request, 'Via:') === FALSE) {
        return 0;
    } else {
        return 1;
    }
}

function identifyProxy($request) {
    if (usedproxy($request)) {
        $via = getHeaderValue ($request, 'Via');
        $for = getHeaderValue ($request, 'X-Forwarded-For');

        if (strpos($request, 'X-BlueCoat-Via:') !== FALSE) {
            $product = 'Bluecoat';
            $product_information = getHeaderValue ($request, 'X-BlueCoat-Via');
        } elseif (stripos($request, 'ISA') !== FALSE) {
            $product = 'Microsoft ISA';
            $product_information = 'none';
        } elseif (stripos($request, 'IWSS') !== FALSE) {
            $product = 'Trend Micro InterScan Web Security Suite (IWSS)';
            $product_information = 'none';
        } elseif (stripos($request, 'NetCache') !== FALSE) {
            $product = 'NetCache NetApp';
            $product_information = 'none';
        } elseif (stripos($request, 'squid') !== FALSE) {
            $product = 'Squid Proxy';
            $product_information = 'none';
        } else {
            $product = 'unknown';
            $product_information = 'none';
        }

        return 'Proxy used (For: '.$for.', Via: '.$via.', Product: '.$product.', Details: '.$product_information.')';
    } else {
        return 'no proxy used';
    }
}

?>
