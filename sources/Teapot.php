<?php
// Nobody expected a teapot here

/* To prevent brewing coffee with a teapot */
if (!defined('\IPS\SUITE_UNIQUE_KEY')) {
    if ($_GET['action'] == 'brew_coffee') {
        header((isset($_SERVER['SERVER_PROTOCOL']) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0') . ' 418 I\'m a teapot');
        header('Content-Type: text/plain');
        header('X-Robots-Tag: noindex, noarchive, nosnippet');
        print_r('To brew a coffee, please use a coffee machine.');
    } else {
        header((isset($_SERVER['SERVER_PROTOCOL']) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0') . ' 404 Not Found');
    }
    exit;
}