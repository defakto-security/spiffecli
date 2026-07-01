# Use vhs to turn this into a GIF
# Run `vhs demo/verify-x509-demo.tape` at the root

Output "/tmp/verify-x509-demo.gif"
Output "/tmp/verify-x509-demo.mp4"

Set FontSize 18
Set Width 1200
Set Height 600
Set TypingSpeed 0.01


Env TESTFILES "internal/x509util/testdata"

Type "# This demonstrates spiffecli's ability to perform generic X.509 verification."
Enter
Type "# Here are some files we'll use for testing."
Enter
Type "ls -loh $TESTFILES"
Enter
Sleep 2000ms
Type "# Let's verify the Let's Encrypt certificate and chain against the Mozilla CA Bundle,
Enter
Type "# downloaded October 2024:"
Enter
Sleep 3000ms
Type "./bin/spiffecli verify x509 --certificate $TESTFILES/letsencrypt-fullchain.pem \"
Enter
Type "    --ca-bundle $TESTFILES/mozilla-2024-10-01.pem --show-path"
Enter
Sleep 2000ms
Type "echo $?"
Enter
Type "# We can do it against a Java keystore, as well:"
Enter
Sleep 3000ms
Type "./bin/spiffecli verify x509 --certificate $TESTFILES/letsencrypt-fullchain.pem \"
Enter
Type "    --ca-bundle $TESTFILES/cacerts-java --ca-format jks --show-path"
Enter
Type "echo $?"
Enter
Sleep 2000ms
Type "# Google includes a cross-signed root, so has two ways to verify a certificate:"
Enter
Sleep 2000ms
Type "./bin/spiffecli verify x509 --certificate $TESTFILES/www.google.com-fullchain.pem \"
Enter
Type "    --ca-bundle $TESTFILES/mozilla-2024-10-01.pem --show-path"
Enter
Sleep 2000ms
Type "echo $?"
Enter
Sleep 2000ms
Type "# Amazon gives us three ways!"
Enter
Sleep 3000ms
Type "./bin/spiffecli verify x509 --certificate $TESTFILES/aws-fullchain.pem \"
Enter
Type "    --ca-bundle $TESTFILES/mozilla-2024-10-01.pem --show-path"
Enter
Sleep 2000ms
Type "echo $?"
Enter
Sleep 2000ms
Type "# This is useful if we're dealing with a very old device that doesn't"
Enter
Type "# have the Amazon Trust Services roots:"
Enter
Sleep 3000ms
Type "./bin/spiffecli verify x509 --certificate $TESTFILES/aws-fullchain.pem \"
Enter
Type "    --ca-bundle $TESTFILES/mozilla-minus-ats.pem --show-path"
Enter
Sleep 2000ms
Type "echo $?"
Enter
Sleep 2000ms
Type "# We can also download the latest Mozilla trust bundle."
Enter
Type "# Chrome, Apple, and Microsoft will be added later."
Enter
Sleep 3000ms
Type "./bin/spiffecli verify x509 --certificate $TESTFILES/aws-fullchain.pem \"
Enter
Type "    --root-program mozilla --show-path"
Enter
Sleep 2000ms
Type "echo $?"
Enter
Sleep 2000ms
Type "# Note that the system roots are different than Mozilla's."
Enter
Sleep 3000ms
Type "./bin/spiffecli verify x509 --certificate $TESTFILES/aws-fullchain.pem \"
Enter
Type "    --system --show-path"
Enter
Sleep 2000ms
Type "echo $?"
Enter
Type "# Finally, let's imagine a world where only Let's Encrypt certificates are trusted."
Enter
Sleep 3000ms
Type "./bin/spiffecli verify x509 --certificate $TESTFILES/aws-fullchain.pem \"
Enter
Type "    --ca-bundle $TESTFILES/only-letsencrypt-roots.pem --show-path"
Enter
Sleep 2000ms
Type "echo $?"
Enter
Sleep 5000ms
