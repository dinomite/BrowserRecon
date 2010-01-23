<?php
/*
 * browserrecon
 *
 * (c) 2008 by Marc Ruef
 * marc.ruef@computec.ch
 * http://www.computec.ch/projekte/browserrecon/
 *
 * Released under the terms and conditions of the
 * GNU General Public License 3.0 (http://gnu.org).
 *
 * Installation:
 * Extract the archive in a folder accessible by your
 * web browser. Include the browserrecon script with
 * the following function call:
 *     include ('browserrecon/inc_browserrecon.php');
 *
 * Use:
 * Use the function browserrecon() to do a web browser
 * fingerprinting with the included utility. The first
 * argument of the function call is the raw http headers
 * sent by the client. You might use the following
 * call to do a live fingerprinting of visiting users:
 *     echo browserrecon(getallheaders());
 *
 * It is also possible to get the data from another
 * source. For example a local file named header.txt:
 *     echo browserrecon(file_get_contents('header.txt')));
 *
 * Or the data sent via a http post form:
 *     echo browserrecon($_POST['header']);
 *
 * Reporting:
 * You are able to change the behavior of the reports
 * sent back by browserrecon(). As second argument you
 * might use the following parameters:
 *     - simple: Identified implementation only
 *     - besthitdetail: Additional hit detail
 *     - list: Unordered list of all matches
 *     - besthitlist: Top ten list of the best matches
 */

/**
 * Identify a browser
 *
 * @param   string  $rawHeaders  The headers, as returned by getallheaders()
 *
 * @return
 */
function browserRecon($rawHeaders, $mode='besthit', $database='') {
    $globalFingerprint = identifyGlobalFingerprint($database, $rawHeaders);
    $possibilities = countHitPossibilities($rawHeaders);
    $matchStatistics = generateMatchStatistics($globalFingerprint);

    return announceFingerprintMatches($matchStatistics, $mode, $possibilities);
}

/**
 * Get a comma-separated list of header keys, in the order that the browser
 * delivered them.
 *
 * @param   string  $rawHeaders  The headers, as returned by getallheaders()
 *
 * @return  string  The header keys as a comma-separated list
 */
function getHeaderOrder($rawHeaders) {
    $order = '';

    foreach ($rawHeaders as $header) {
        list($key, $value) = explode(':', $header, 2);

        $order .= $key . ', ';
    }
    rtrim($order, ', ');

    return $order;
}

/**
 * Get the maximum number of hits that this browser can get, based upon the
 * number of headers that it provided which we know about.
 *
 * @param   string  $rawHeaders  The headers, as returned by getallheaders()
 *
 * @return  integer The count of hit possibilities
 */
function countHitPossibilities($rawHeaders) {
    array_key_exists('User-Agent', $rawHeaders) ? ++$count : '';
    array_key_exists('Accept', $rawHeaders) ? ++$count : '';
    array_key_exists('Accept-Language', $rawHeaders) ? ++$count : '';
    array_key_exists('Accept-Encoding', $rawHeaders) ? ++$count : '';
    array_key_exists('Accept-Charset', $rawHeaders) ? ++$count : '';
    array_key_exists('Keep-Alive', $rawHeaders) ? ++$count : '';
    array_key_exists('Connection', $rawHeaders) ? ++$count : '';
    array_key_exists('Cache-Control', $rawHeaders) ? ++$count : '';
    array_key_exists('UA-Pixels', $rawHeaders) ? ++$count : '';
    array_key_exists('UA-Color', $rawHeaders) ? ++$count : '';
    array_key_exists('UA-OS', $rawHeaders) ? ++$count : '';
    array_key_exists('UA-CPU', $rawHeaders) ? ++$count : '';
    array_key_exists('TE', $rawHeaders) ? ++$count : '';
    getHeaderOrder($rawHeaders) != '' ? ++$count : '';

    return $count;
}

/**
 * Find each of the headers we care about in the databases.
 *
 * @param   string  $database   The database file prefix to use
 * @param   string  $rawHeaders  The headers, as returned by getallheaders()
 *
 * @return  string  Array of browsers that match
 */
function identifyGlobalFingerprint($database, $rawHeaders) {
    $matches = array();
    $matches = combineArrays($matches, findMatchInDatabase($database.'user-agent.fdb', $rawHeaders['User-Agent']));
    $matches = combineArrays($matches, findMatchInDatabase($database.'accept.fdb', $rawHeaders['Accept']));
    $matches = combineArrays($matches, findMatchInDatabase($database.'accept-language.fdb', $rawHeaders['Accept-Language']));
    $matches = combineArrays($matches, findMatchInDatabase($database.'accept-encoding.fdb', $rawHeaders['Accept-Encoding']));
    $matches = combineArrays($matches, findMatchInDatabase($database.'accept-charset.fdb', $rawHeaders['Accept-Charset']));
    $matches = combineArrays($matches, findMatchInDatabase($database.'keep-alive.fdb', $rawHeaders['Keep-Alive']));
    $matches = combineArrays($matches, findMatchInDatabase($database.'connection.fdb', $rawHeaders['Connection']));
    $matches = combineArrays($matches, findMatchInDatabase($database.'cache-control.fdb', $rawHeaders['Cache-Control']));
    $matches = combineArrays($matches, findMatchInDatabase($database.'ua-pixels.fdb', $rawHeaders['UA-Pixels']));
    $matches = combineArrays($matches, findMatchInDatabase($database.'ua-color.fdb', $rawHeaders['UA-Color']));
    $matches = combineArrays($matches, findMatchInDatabase($database.'ua-os.fdb', $rawHeaders['UA-OS']));
    $matches = combineArrays($matches, findMatchInDatabase($database.'ua-cpu.fdb', $rawHeaders['UA-CPU']));
    $matches = combineArrays($matches, findMatchInDatabase($database.'te.fdb', $rawHeaders['TE']));
    $matches = combineArrays($matches, findMatchInDatabase($database.'header-order.fdb', getHeaderOrder($rawHeaders)));

    return $matches;
}

/**
 * Get a list of browsers that match the given header.
 *
 * @param   string  $databaseFile   The DB file to read headers from
 * @param   string  $headerValue    The header from the browser
 *
 * @return  array   Array of browsers that match
 */
function findMatchInDatabase ($databaseFile, $headerValue) {
    // Get the whole database as an array of lines
    $database = file($databaseFile);
    $matches = array();

    foreach($database as $entry) {
        // Lines are "Browser name;header value"
        list($dbBrowser, $dbValue) = explode(';', $entry, 2);

        // Append this browser name to the matches
        if ($headerValue == rtrim($dbValue))
            $matches[] = $dbBrowser;
    }

    return $matches;
}

/**
 * @param   array   $matches   Browsers that matched
 *
 * @return  string  Lines with the name of a browser & the number of header matches
 */
function generateMatchStatistics($matches) {
    $uniqueMatches = array_unique($matches);

    foreach ($uniqueMatches as $match) {
        $matchStatistic .= $match .'='. countif($matches, $match) ."\n";
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
    foreach ($input as $entry) {
        if ($entry == $search)
            $sum++;
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
            $resultList .= $matchName.': '. $matchCount."<br>\n";
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
                    $hitList .= "<br>\n";
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

/**
 * Combine two arrays, without any merging jazz.
 */
function combineArrays($one, $two) {
    foreach ($two as $item) {
        $one[] = $item;
    }

    return $one;
}

//////////////  ONLY USED FOR ADDING FINGERPRINTS  ////////////////
function addToDatabase ($databaseFile, $implementation, $value) {
    print "addToDB-dbFile: $databaseFile; impl: $implementation; value: $value<br>\n";
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

function saveAllFingerprintsToDatabase ($rawHeaders, $implementation) {
    saveNewFingerprintToDatabase ('user-agent.fdb', $implementation, $rawHeaders['User-Agent']);
    saveNewFingerprintToDatabase ('accept.fdb', $implementation, $rawHeaders['Accept']);
    saveNewFingerprintToDatabase ('accept-language.fdb', $implementation, $rawHeaders['Accept-Language']);
    saveNewFingerprintToDatabase ('accept-encoding.fdb', $implementation, $rawHeaders['Accept-Encoding']);
    saveNewFingerprintToDatabase ('accept-charset.fdb', $implementation, $rawHeaders['Accept-Charset']);
    saveNewFingerprintToDatabase ('keep-alive.fdb', $implementation, $rawHeaders['Keep-Alive']);
    saveNewFingerprintToDatabase ('connection.fdb', $implementation, $rawHeaders['Connection']);
    saveNewFingerprintToDatabase ('cache-control.fdb', $implementation, $rawHeaders['Cache-Control']);
    saveNewFingerprintToDatabase ('ua-pixels.fdb', $implementation, $rawHeaders['UA-Pixels']);
    saveNewFingerprintToDatabase ('ua-color.fdb', $implementation, $rawHeaders['UA-Color']);
    saveNewFingerprintToDatabase ('ua-os.fdb', $implementation, $rawHeaders['UA-OS']);
    saveNewFingerprintToDatabase ('ua-cpu.fdb', $implementation, $rawHeaders['UA-CPU']);
    saveNewFingerprintToDatabase ('te.fdb', $implementation, $rawHeaders['TE']);
    saveNewFingerprintToDatabase ('header-order.fdb', $implementation, getHeaderOrder($rawHeaders));
}

function saveNewFingerprintToDatabase ($filename, $implementation, $value) {
    print "SNFTD\n";
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
