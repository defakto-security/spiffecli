# Use vhs to turn this into a GIF
# Run `vhs demo/inspect-jwt.tape` at the root

Output "/tmp/inspect-jwt.gif"
Output "/tmp/inspect-jwt.mp4"

Set FontSize 18
Set Width 1200
Set Height 600
Set TypingSpeed 0.01

Env TESTFILES "internal/jwtinspect/testdata"

Type "# This demonstrates spiffecli's ability to perform JWT inspection."
Enter
Type "# Here are some files we'll use for testing."
Enter
Type "ls -loh $TESTFILES/*.jwt"
Enter
Sleep 2000ms
Type "# Let's inspect an SVID. By default, the output is in JSON. "
Enter
Sleep 3000ms
Type "./bin/spiffecli inspect jwt --filename $TESTFILES/svid.jwt"
Enter
Sleep 2000ms
Enter
Type "# Let's add the header information."
Enter
Sleep 3000ms
Type "./bin/spiffecli inspect jwt --filename $TESTFILES/svid.jwt --headers"
Enter
Sleep 2000ms
Enter
Type "# We can also output YAML."
Enter
Sleep 3000ms
Type "./bin/spiffecli inspect jwt --filename $TESTFILES/svid.jwt  --headers --format yaml"
Enter
Sleep 2000ms
Enter
Type "# We can colorize the output."
Enter
Sleep 3000ms
Type "./bin/spiffecli inspect jwt --filename $TESTFILES/svid.jwt  --headers --format yaml --color"
Enter
Sleep 2000ms
Enter
Type "# We can also print a human-readable summary of the JWT."
Enter
Sleep 3000ms
Type "./bin/spiffecli inspect jwt --filename $TESTFILES/svid.jwt --format summary"
Enter
Sleep 2000ms
Enter
Type "# If it's not an SVID, it will tell us why."
Enter
Sleep 3000ms
Type "./bin/spiffecli inspect jwt --filename $TESTFILES/badexp.jwt --format summary"
Enter
Sleep 2000ms
