<?php
// Include the browserrecon application
include('inc_browserrecon.php');

$rawHeaders = getallheaders();

echo "<html><body>\n";

if (array_key_exists('browser', $_GET)) {
    // If they gave a browser, save it to the DB
    echo "browser: " . $_GET['browser'] . "<br>\n";
    saveAllFingerprintsToDatabase($rawHeaders, $_GET['browser']);
} else {
    echo "
        <form action='index.php' method='GET'>
            Browser: <input type='text' name='browser' />
            <br>
            UA is ". $rawHeaders['User-Agent'] ."
        </form>
    ";
}
?>

<h1>Best Hits:</h1>
<?php echo browserRecon($rawHeaders, 'besthitlist');?>
<br>
<h1>Full hit list</h1>
<?php echo browserRecon($rawHeaders, 'list');?>

</body></html>
