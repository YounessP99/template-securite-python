/*
 * Regles YARA d'exemple pour le TP2.
 */

rule Suspicious_Downloader
{
    meta:
        author = "esgi"
        description = "Telechargement + execution d'une charge distante"
    strings:
        $dll = "urlmon.dll" nocase
        $api = "URLDownloadToFile" nocase
        $run = "WinExec" nocase
    condition:
        2 of them
}

rule Reverse_Shell
{
    meta:
        author = "esgi"
        description = "Socket sortante + shell de commande"
    strings:
        $ws = "WSASocket" nocase
        $sh = "cmd.exe" nocase
    condition:
        $ws and $sh
}

rule Keylogger
{
    meta:
        author = "esgi"
        description = "Hook clavier"
    strings:
        $hook = "SetWindowsHookEx" nocase
        $key = "GetAsyncKeyState" nocase
    condition:
        any of them
}