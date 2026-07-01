# Use vhs to turn this into a GIF
# Run `vhs demo/inspect-jwks.tape` at the root

Output "/tmp/inspect-jwks.gif"
Output "/tmp/inspect-jwks.mp4"

Set FontSize 18
Set Width 1200
Set Height 600
Set TypingSpeed 0.01

Env TESTFILES "internal/bundle/testdata"

Type "# This demonstrates spiffecli's ability"
Enter
Type "# to perform JSON Web Key Set (JWKS) inspection,"
Enter
Type "# either from a local file or a URL."
Enter
Type "# Here are some files we'll use for testing."
Enter
Type "ls -loh $TESTFILES/*.jwks"
Enter
Sleep 2000ms
Type "# Let's inspect a JWKS with a single key. By default, the output is in JSON."
Enter
Sleep 3000ms
Type "./bin/spiffecli inspect jwks --location $TESTFILES/single.jwks"
Enter
Enter
Sleep 2000ms
Enter
Type "# Not super exciting since JWKS is already JSON, but we can colorize and indent."
Enter
Sleep 3000ms
Type "./bin/spiffecli inspect jwks --location $TESTFILES/single.jwks --color --indent"
Enter
Sleep 2000ms
Enter
Type "# We can also output YAML."
Enter
Sleep 3000ms
Type "./bin/spiffecli inspect jwks --location $TESTFILES/single.jwks --format yaml --color"
Enter
Sleep 2000ms
Enter

Type "# Here's a human-readable summary of the JWKS."
Enter
Sleep 3000ms
Type "./bin/spiffecli inspect jwks --location $TESTFILES/single.jwks --format summary"
Enter
Sleep 2000ms
Enter
Type "# And if we only want the key ids (trust domains if it's a SPIFFE bundle), 
Enter
Type "# we have that option."
Enter
Sleep 3000ms
Type "./bin/spiffecli inspect jwks --location $TESTFILES/single.jwks --format key-ids"
Enter
Sleep 2000ms
Type "# Conveniently, we can also check remote JWKS endpoints."
Enter
Sleep 3000ms
Type "./bin/spiffecli inspect jwks --location https://www.googleapis.com/oauth2/v3/certs --format summary"
Enter
Sleep 2000ms