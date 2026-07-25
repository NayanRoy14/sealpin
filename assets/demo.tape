# VHS tape for the sealpin README demo. Record with: vhs assets/demo.tape
# Requires: vhs, ttyd, ffmpeg, and `sealpin` on PATH.

Output assets/demo.gif

Require sealpin

Set Shell bash
Set FontSize 13
Set Width 1120
Set Height 900
Set Padding 22
Set Theme "Dracula"
Set TypingSpeed 50ms

Hide
Type "cd assets/demo && clear"
Enter
Show

Sleep 500ms
Type "sealpin scan --config config.json --manifest-dir manifests"
Sleep 700ms
Enter
Sleep 4s
