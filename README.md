<p align="center"> <img src="https://raw.githubusercontent.com/qeeqbox/session-fixation/main/session-fixation.png"></p>

A threat actor may trick a user into using a known session identifier to log in. after logging in, the session identifier is used to gain access to the user's account.

## Example #1
1. Threat actor visits the vulnerable website without logging in and obtains a session identifier
2. Threat actor tricks bob into logging into the vulnerable website using the session identifier
3. Threat actor uses the same session identifier to gain unauthorized access to bob's account

## Impact
Vary

## Risk
- Gain unauthorized access

## Redemption
- Identity confirmation
- Regenerate session ids at authentication
- Timeout and replace old session ids
- Store ids in HTTP cookies

## ID
ecd7744c-83b0-406c-a58d-63d057a5570b

## References
- [wiki](https://en.wikipedia.org/wiki/session_fixation)
