rule Persistence_Run_Key
{
    meta:
        author = "Youness Parbotteea"
        description = "Cle de demarrage automatique et mutex global"
    strings:
        $run = "CurrentVersion\\Run" nocase
        $mutex = "Global\\" nocase
    condition:
        all of them
}

rule C2_Gate
{
    meta:
        author = "Youness Parbotteea"
        description = "Contact avec un serveur de commande et controle"
    strings:
        $gate = "/gate.php" nocase
        $host = "c2-" nocase
    condition:
        all of them
}