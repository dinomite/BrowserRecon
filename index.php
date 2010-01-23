<?php
// Include the browserrecon application
include('inc_browserrecon.php');

$rawHeaders = getallheaders();

echo "<html><body>\n";
echo browserRecon($rawHeaders, 'besthitdetail');
echo "\n<hr>\n";
echo browserRecon($rawHeaders, 'besthitlist');
echo "\n<hr>\n";
echo browserRecon($rawHeaders, 'list');

saveAllFingerprintsToDatabase($rawHeaders, 'Mozilla Firefox 3.5.7 Mac OS 10.5.3');
echo "\n</body></html>\n";

/*
// Do the web browser fingerprinting
$browser = browserRecon(getallheaders());

if($_SERVER['QUERY_STRING'] == 'pic'){
    $font = 2;
    $width  = imagefontwidth($font) * strlen($browser);
    $height = imagefontheight($font);
    $im = imagecreate($width, $height);

    $x = imagesx($im) - $width ;
    $y = imagesy($im) - $height;
    $background_color = imagecolorallocate($im, 242, 242, 242);
    $text_color = imagecolorallocate($im, 0, 0, 0);
    $trans_color = $background_color;
    imagecolortransparent($im, $trans_color);
    imagestring($im, $font, $x, $y,  $browser, $text_color);

    if(function_exists('imagegif')){
        header('Content-type: image/gif');
        imagegif($im);
    }elseif (function_exists('imagejpeg')){
        header('Content-type: image/jpeg');
        imagejpeg($im, '', 0.5);
    }elseif(function_exists('imagepng')){
        header('Content-type: image/png');
        imagepng($im);
    }
    imagedestroy($im);
}else{
    echo $browser;
}
*/
