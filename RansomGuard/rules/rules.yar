rule Ransomware_Pro_Detector
{
    meta:
        description = "Advanced ransomware detection by filename & content"
        author = "Janjitha"
        last_modified = "2025-08-12"
        severity = "critical"
    strings:
        $exts = /.*\.(locked|encrypted|crypt|cry|enc|enciphered|lockedfile|paycrypt|paybtc|paybit|locky|cryptolocker|r5a|aes256|btc|pay|secure|vault|lockeddata)(\..*)?$/ nocase
        $note1 = /readme(\.txt)?$/ nocase
        $note2 = /how_to_decrypt(\.txt)?$/ nocase
        $note3 = /decrypt_instructions(\.txt)?$/ nocase
        $note4 = /recover_files(\.txt)?$/ nocase
        $note5 = /(ransom|payment|unlock)_note(\.txt)?$/ nocase
        $note6 = /(!!!|HELP)_DECRYPT(\.txt)?$/ nocase

        $p1 = "all your files have been encrypted" nocase
        $p2 = "your files are locked" nocase
        $p3 = "your documents, photos, databases" nocase
        $p4 = "pay bitcoin" nocase
        $p5 = "send bitcoin" nocase
        $p6 = "send btc" nocase
        $p7 = "btc wallet" nocase
        $p8 = "payment required" nocase
        $p9 = "decrypt your files" nocase
        $p10 = "to recover your files" nocase
        $p11 = "data has been encrypted" nocase
        $p12 = "contact us to get the decryption key" nocase
        $p13 = "buy a decryption key" nocase
        $p14 = "install tor browser" nocase
        $p15 = "personal id" nocase
        $p16 = "unique key" nocase
        $p17 = "within 72 hours" nocase
        $p18 = "or your files will be lost" nocase
        $p19 = "restore your files" nocase
        $p20 = "decryptor" nocase

        $obs1 = /d[\s_]*e[\s_]*c[\s_]*r[\s_]*y[\s_]*p[\s_]*t/i
        $obs2 = /e[\s_]*n[\s_]*c[\s_]*r[\s_]*y[\s_]*p[\s_]*t/i
    condition:
        any of ($exts, $note1, $note2, $note3, $note4, $note5, $note6) or
        any of ($p1, $p2, $p3, $p4, $p5, $p6, $p7, $p8, $p9, $p10,
                $p11, $p12, $p13, $p14, $p15, $p16, $p17, $p18, $p19, $p20,
                $obs1, $obs2)
}
