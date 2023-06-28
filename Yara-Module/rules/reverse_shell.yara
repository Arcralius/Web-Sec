rule ReverseShellDetection_JS
{
    meta:
        description = "Detects reverse shell activity in JavaScript files"
        author = "Your Name"

    strings:
	    /* List of strings commonly found in reverse shells */
	    $string1 = "eval(String.fromCharCode"
	    $string2 = "btoa("
	    $string3 = "Function('return this')"
	    $string4 = "getInputStream()"
	    $string5 = "getOutputStream()"
	    $string6 = "net.Socket()"
	    $string7 = "net.socket()"


    condition:
        all of them or any of them
}

