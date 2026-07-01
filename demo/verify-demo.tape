# Use vhs to turn this into a GIF
# Prerequisites:
# 1. Use ./bin/spiffecli run to start a simulated workload API
# 2. Copy the acme-corp socket and put it in $ACME_SOCK
# 3. Create a './tmp' directory
# 4. Serve the './tmp' directory a local http server on port 8000
#    (`python3 -m http.server 8000` works great)
# Run `vhs demo/verify-demo.tape` at the root

Output "/tmp/verify-demo.gif"
Output "/tmp/verify-demo.mp4"

Set FontSize 18
Set Width 1200
Set Height 600
Set TypingSpeed 0.01

Env BUNDLE "tmp/acme-bundle.json"
Env JWT "tmp/jwt.json"

Type "# This demonstrates spiffecli's ability to verify JWTs against a bundle on disk, "
Enter
Type "# or one fetched via HTTP(s)."
Enter
Type "# We'll use ./tmp to store temporary files"
Enter
Type "ls -loh tmp"
Enter
Sleep 2000ms
Type "# Here are some environment variables we'll use"
Enter
Type "echo $BUNDLE"
Enter
Type "echo $JWT"
Enter
Sleep 2000ms
Type "# The workload is already running. Here's the socket we'll use:"
Enter
Type "echo $ACME_SOCK"
Enter 
Type "# First, we get the bundle."
Enter
Sleep 3000ms
Type "./bin/spiffecli get bundle jwt --filename $BUNDLE -t acme-corp -s unix://$ACME_SOCK"
Enter
Sleep 2000ms
Type "ls -loh tmp"
Enter
Type "# Second, we get a JWT to validate."
Enter
Sleep 3000ms
Type "./bin/spiffecli get jwt-svid --audiences http://example.org --filename $JWT -s unix://$ACME_SOCK" 
Enter
Type "ls -loh tmp"
Enter
Sleep 2000ms
Type "# Let's verify it!"
Enter
Sleep 2000ms
Type "./bin/spiffecli verify jwt-svid --bundle $BUNDLE --trust-domain acme-corp \"
Enter
Type "     --filename $JWT --audiences http://example.org"
Enter
Sleep 2000ms
Type "echo $?"
Enter
Sleep 2000ms
Type "# Then let's try verifying with a bundle provided by an http server."
Enter
Sleep 3000ms
Type "./bin/spiffecli verify jwt-svid --bundle http://localhost:8000/acme-bundle.json \"
Enter
Type "     --trust-domain acme-corp --filename $JWT --audiences http://example.org"
Enter
Sleep 2000ms
Type "echo $?"
Enter
Type "# It worked!"
Enter
Sleep 5000ms
Hide
Type "rm -f $BUNDLE"
Enter
Type "rm -f $JWT"
Enter
