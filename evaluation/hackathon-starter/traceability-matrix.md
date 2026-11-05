# Control-path traceability matrix

One row per (threat agent, asset) pair: shortest route over the data flows from where the agent starts to an element holding (else processing) the asset, the controls crossed, the controls effective against that agent, and a verdict. Worst first.

| Threat agent | Asset | Shortest path | Controls crossed | Effective controls | Verdict |
|---|---|---|---|---|---|
| Compromised third party: Oauth2 Refresh identity provider | Secret TWITCH_CLIENT_SECRET | Oauth2 Refresh identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth2 Refresh identity provider | Secret PAYPAL_SECRET | Oauth2 Refresh identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth2 Refresh identity provider | Secret MICROSOFT_CLIENT_SECRET | Oauth2 Refresh identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth2 Refresh identity provider | Secret FOURSQUARE_APIKEY | Oauth2 Refresh identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth2 Refresh identity provider | Secret GROQ_API_KEY | Oauth2 Refresh identity provider -> passport -> app -> ai-agent | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth2 Refresh identity provider | Secret TUMBLR_SECRET | Oauth2 Refresh identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth2 Refresh identity provider | Secret QUICKBOOKS_CLIENT_SECRET | Oauth2 Refresh identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth2 Refresh identity provider | Secret GITHUB_SECRET | Oauth2 Refresh identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth2 Refresh identity provider | Secret HERE_API_KEY | Oauth2 Refresh identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth2 Refresh identity provider | Secret SMTP_PASSWORD | Oauth2 Refresh identity provider -> passport -> Unresolved HTTP target -> contact -> nodemailer | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth2 Refresh identity provider | Secret FACEBOOK_SECRET | Oauth2 Refresh identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth2 Refresh identity provider | Secret X_SECRET | Oauth2 Refresh identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth2 Refresh identity provider | Secret GOOGLE_CLIENT_SECRET | Oauth2 Refresh identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth2 Refresh identity provider | Secret GOOGLE_MAP_API_KEY | Oauth2 Refresh identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth2 Refresh identity provider | Secret TWILIO_TOKEN | Oauth2 Refresh identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth2 Refresh identity provider | Secret SESSION_SECRET | Oauth2 Refresh identity provider -> passport -> app | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth2 Refresh identity provider | Secret LINKEDIN_SECRET | Oauth2 Refresh identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth2 Refresh identity provider | Secret LASTFM_SECRET | Oauth2 Refresh identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth2 Refresh identity provider | Secret GOOGLE_API_KEY | Oauth2 Refresh identity provider -> passport -> Unresolved HTTP target -> contact | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth2 Refresh identity provider | Secret GIPHY_API_KEY | Oauth2 Refresh identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth2 Refresh identity provider | Secret DISCORD_CLIENT_SECRET | Oauth2 Refresh identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: discord.com | Secret TWITCH_CLIENT_SECRET | discord.com -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: discord.com | Secret PAYPAL_SECRET | discord.com -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: discord.com | Secret MICROSOFT_CLIENT_SECRET | discord.com -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: discord.com | Secret FOURSQUARE_APIKEY | discord.com -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: discord.com | Secret GROQ_API_KEY | discord.com -> passport -> app -> ai-agent | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: discord.com | Secret TUMBLR_SECRET | discord.com -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: discord.com | Secret QUICKBOOKS_CLIENT_SECRET | discord.com -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: discord.com | Secret GITHUB_SECRET | discord.com -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: discord.com | Secret HERE_API_KEY | discord.com -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: discord.com | Secret SMTP_PASSWORD | discord.com -> passport -> Unresolved HTTP target -> contact -> nodemailer | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: discord.com | Secret FACEBOOK_SECRET | discord.com -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: discord.com | Secret X_SECRET | discord.com -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: discord.com | Secret GOOGLE_CLIENT_SECRET | discord.com -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: discord.com | Secret GOOGLE_MAP_API_KEY | discord.com -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: discord.com | Secret TWILIO_TOKEN | discord.com -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: discord.com | Secret SESSION_SECRET | discord.com -> passport -> app | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: discord.com | Secret LINKEDIN_SECRET | discord.com -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: discord.com | Secret LASTFM_SECRET | discord.com -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: discord.com | Secret GOOGLE_API_KEY | discord.com -> passport -> Unresolved HTTP target -> contact | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: discord.com | Secret GIPHY_API_KEY | discord.com -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: discord.com | Secret DISCORD_CLIENT_SECRET | discord.com -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth1 identity provider | Secret TWITCH_CLIENT_SECRET | Oauth1 identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth1 identity provider | Secret PAYPAL_SECRET | Oauth1 identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth1 identity provider | Secret MICROSOFT_CLIENT_SECRET | Oauth1 identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth1 identity provider | Secret FOURSQUARE_APIKEY | Oauth1 identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth1 identity provider | Secret GROQ_API_KEY | Oauth1 identity provider -> passport -> app -> ai-agent | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth1 identity provider | Secret TUMBLR_SECRET | Oauth1 identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth1 identity provider | Secret QUICKBOOKS_CLIENT_SECRET | Oauth1 identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth1 identity provider | Secret GITHUB_SECRET | Oauth1 identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth1 identity provider | Secret HERE_API_KEY | Oauth1 identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth1 identity provider | Secret SMTP_PASSWORD | Oauth1 identity provider -> passport -> Unresolved HTTP target -> contact -> nodemailer | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth1 identity provider | Secret FACEBOOK_SECRET | Oauth1 identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth1 identity provider | Secret X_SECRET | Oauth1 identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth1 identity provider | Secret GOOGLE_CLIENT_SECRET | Oauth1 identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth1 identity provider | Secret GOOGLE_MAP_API_KEY | Oauth1 identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth1 identity provider | Secret TWILIO_TOKEN | Oauth1 identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth1 identity provider | Secret SESSION_SECRET | Oauth1 identity provider -> passport -> app | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth1 identity provider | Secret LINKEDIN_SECRET | Oauth1 identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth1 identity provider | Secret LASTFM_SECRET | Oauth1 identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth1 identity provider | Secret GOOGLE_API_KEY | Oauth1 identity provider -> passport -> Unresolved HTTP target -> contact | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth1 identity provider | Secret GIPHY_API_KEY | Oauth1 identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Oauth1 identity provider | Secret DISCORD_CLIENT_SECRET | Oauth1 identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: GitHub API | Secret TWITCH_CLIENT_SECRET | GitHub API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: GitHub API | Secret PAYPAL_SECRET | GitHub API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: GitHub API | Secret MICROSOFT_CLIENT_SECRET | GitHub API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: GitHub API | Secret FOURSQUARE_APIKEY | GitHub API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: GitHub API | Secret GROQ_API_KEY | GitHub API -> api -> app -> ai-agent | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: GitHub API | Secret TUMBLR_SECRET | GitHub API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: GitHub API | Secret QUICKBOOKS_CLIENT_SECRET | GitHub API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: GitHub API | Secret GITHUB_SECRET | GitHub API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: GitHub API | Secret HERE_API_KEY | GitHub API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: GitHub API | Secret SMTP_PASSWORD | GitHub API -> api -> Unresolved HTTP target -> contact -> nodemailer | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: GitHub API | Secret FACEBOOK_SECRET | GitHub API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: GitHub API | Secret X_SECRET | GitHub API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: GitHub API | Secret GOOGLE_CLIENT_SECRET | GitHub API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: GitHub API | Secret GOOGLE_MAP_API_KEY | GitHub API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: GitHub API | Secret TWILIO_TOKEN | GitHub API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: GitHub API | Secret SESSION_SECRET | GitHub API -> api -> app | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: GitHub API | Secret LINKEDIN_SECRET | GitHub API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: GitHub API | Secret LASTFM_SECRET | GitHub API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: GitHub API | Secret GOOGLE_API_KEY | GitHub API -> api -> Unresolved HTTP target -> contact | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: GitHub API | Secret GIPHY_API_KEY | GitHub API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: GitHub API | Secret DISCORD_CLIENT_SECRET | GitHub API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Twilio API | Secret TWITCH_CLIENT_SECRET | Twilio API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Twilio API | Secret PAYPAL_SECRET | Twilio API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Twilio API | Secret MICROSOFT_CLIENT_SECRET | Twilio API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Twilio API | Secret FOURSQUARE_APIKEY | Twilio API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Twilio API | Secret GROQ_API_KEY | Twilio API -> api -> app -> ai-agent | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Twilio API | Secret TUMBLR_SECRET | Twilio API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Twilio API | Secret QUICKBOOKS_CLIENT_SECRET | Twilio API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Twilio API | Secret GITHUB_SECRET | Twilio API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Twilio API | Secret HERE_API_KEY | Twilio API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Twilio API | Secret SMTP_PASSWORD | Twilio API -> api -> Unresolved HTTP target -> contact -> nodemailer | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Twilio API | Secret FACEBOOK_SECRET | Twilio API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Twilio API | Secret X_SECRET | Twilio API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Twilio API | Secret GOOGLE_CLIENT_SECRET | Twilio API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Twilio API | Secret GOOGLE_MAP_API_KEY | Twilio API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Twilio API | Secret TWILIO_TOKEN | Twilio API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Twilio API | Secret SESSION_SECRET | Twilio API -> api -> app | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Twilio API | Secret LINKEDIN_SECRET | Twilio API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Twilio API | Secret LASTFM_SECRET | Twilio API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Twilio API | Secret GOOGLE_API_KEY | Twilio API -> api -> Unresolved HTTP target -> contact | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Twilio API | Secret GIPHY_API_KEY | Twilio API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Twilio API | Secret DISCORD_CLIENT_SECRET | Twilio API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Last.fm API | Secret TWITCH_CLIENT_SECRET | Last.fm API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Last.fm API | Secret PAYPAL_SECRET | Last.fm API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Last.fm API | Secret MICROSOFT_CLIENT_SECRET | Last.fm API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Last.fm API | Secret FOURSQUARE_APIKEY | Last.fm API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Last.fm API | Secret GROQ_API_KEY | Last.fm API -> api -> app -> ai-agent | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Last.fm API | Secret TUMBLR_SECRET | Last.fm API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Last.fm API | Secret QUICKBOOKS_CLIENT_SECRET | Last.fm API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Last.fm API | Secret GITHUB_SECRET | Last.fm API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Last.fm API | Secret HERE_API_KEY | Last.fm API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Last.fm API | Secret SMTP_PASSWORD | Last.fm API -> api -> Unresolved HTTP target -> contact -> nodemailer | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Last.fm API | Secret FACEBOOK_SECRET | Last.fm API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Last.fm API | Secret X_SECRET | Last.fm API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Last.fm API | Secret GOOGLE_CLIENT_SECRET | Last.fm API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Last.fm API | Secret GOOGLE_MAP_API_KEY | Last.fm API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Last.fm API | Secret TWILIO_TOKEN | Last.fm API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Last.fm API | Secret SESSION_SECRET | Last.fm API -> api -> app | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Last.fm API | Secret LINKEDIN_SECRET | Last.fm API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Last.fm API | Secret LASTFM_SECRET | Last.fm API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Last.fm API | Secret GOOGLE_API_KEY | Last.fm API -> api -> Unresolved HTTP target -> contact | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Last.fm API | Secret GIPHY_API_KEY | Last.fm API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Last.fm API | Secret DISCORD_CLIENT_SECRET | Last.fm API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: pubchem.ncbi.nlm.nih.gov | Secret TWITCH_CLIENT_SECRET | pubchem.ncbi.nlm.nih.gov -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: pubchem.ncbi.nlm.nih.gov | Secret PAYPAL_SECRET | pubchem.ncbi.nlm.nih.gov -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: pubchem.ncbi.nlm.nih.gov | Secret MICROSOFT_CLIENT_SECRET | pubchem.ncbi.nlm.nih.gov -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: pubchem.ncbi.nlm.nih.gov | Secret FOURSQUARE_APIKEY | pubchem.ncbi.nlm.nih.gov -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: pubchem.ncbi.nlm.nih.gov | Secret GROQ_API_KEY | pubchem.ncbi.nlm.nih.gov -> api -> app -> ai-agent | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: pubchem.ncbi.nlm.nih.gov | Secret TUMBLR_SECRET | pubchem.ncbi.nlm.nih.gov -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: pubchem.ncbi.nlm.nih.gov | Secret QUICKBOOKS_CLIENT_SECRET | pubchem.ncbi.nlm.nih.gov -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: pubchem.ncbi.nlm.nih.gov | Secret GITHUB_SECRET | pubchem.ncbi.nlm.nih.gov -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: pubchem.ncbi.nlm.nih.gov | Secret HERE_API_KEY | pubchem.ncbi.nlm.nih.gov -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: pubchem.ncbi.nlm.nih.gov | Secret SMTP_PASSWORD | pubchem.ncbi.nlm.nih.gov -> api -> Unresolved HTTP target -> contact -> nodemailer | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: pubchem.ncbi.nlm.nih.gov | Secret FACEBOOK_SECRET | pubchem.ncbi.nlm.nih.gov -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: pubchem.ncbi.nlm.nih.gov | Secret X_SECRET | pubchem.ncbi.nlm.nih.gov -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: pubchem.ncbi.nlm.nih.gov | Secret GOOGLE_CLIENT_SECRET | pubchem.ncbi.nlm.nih.gov -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: pubchem.ncbi.nlm.nih.gov | Secret GOOGLE_MAP_API_KEY | pubchem.ncbi.nlm.nih.gov -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: pubchem.ncbi.nlm.nih.gov | Secret TWILIO_TOKEN | pubchem.ncbi.nlm.nih.gov -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: pubchem.ncbi.nlm.nih.gov | Secret SESSION_SECRET | pubchem.ncbi.nlm.nih.gov -> api -> app | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: pubchem.ncbi.nlm.nih.gov | Secret LINKEDIN_SECRET | pubchem.ncbi.nlm.nih.gov -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: pubchem.ncbi.nlm.nih.gov | Secret LASTFM_SECRET | pubchem.ncbi.nlm.nih.gov -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: pubchem.ncbi.nlm.nih.gov | Secret GOOGLE_API_KEY | pubchem.ncbi.nlm.nih.gov -> api -> Unresolved HTTP target -> contact | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: pubchem.ncbi.nlm.nih.gov | Secret GIPHY_API_KEY | pubchem.ncbi.nlm.nih.gov -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: pubchem.ncbi.nlm.nih.gov | Secret DISCORD_CLIENT_SECRET | pubchem.ncbi.nlm.nih.gov -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Groq API | Secret TWITCH_CLIENT_SECRET | Groq API -> ai-agent -> app -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Groq API | Secret PAYPAL_SECRET | Groq API -> ai-agent -> app -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Groq API | Secret MICROSOFT_CLIENT_SECRET | Groq API -> ai-agent -> app -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Groq API | Secret FOURSQUARE_APIKEY | Groq API -> ai-agent -> app -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Groq API | Secret GROQ_API_KEY | Groq API -> ai-agent | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Groq API | Secret TUMBLR_SECRET | Groq API -> ai-agent -> app -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Groq API | Secret QUICKBOOKS_CLIENT_SECRET | Groq API -> ai-agent -> app -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Groq API | Secret GITHUB_SECRET | Groq API -> ai-agent -> app -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Groq API | Secret HERE_API_KEY | Groq API -> ai-agent -> app -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Groq API | Secret SMTP_PASSWORD | Groq API -> ai-agent -> user -> nodemailer | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Groq API | Secret FACEBOOK_SECRET | Groq API -> ai-agent -> app -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Groq API | Secret X_SECRET | Groq API -> ai-agent -> app -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Groq API | Secret GOOGLE_CLIENT_SECRET | Groq API -> ai-agent -> app -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Groq API | Secret GOOGLE_MAP_API_KEY | Groq API -> ai-agent -> app -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Groq API | Secret TWILIO_TOKEN | Groq API -> ai-agent -> app -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Groq API | Secret SESSION_SECRET | Groq API -> ai-agent -> app | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Groq API | Secret LINKEDIN_SECRET | Groq API -> ai-agent -> app -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Groq API | Secret LASTFM_SECRET | Groq API -> ai-agent -> app -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Groq API | Secret GOOGLE_API_KEY | Groq API -> ai-agent -> app -> contact | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Groq API | Secret GIPHY_API_KEY | Groq API -> ai-agent -> app -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Groq API | Secret DISCORD_CLIENT_SECRET | Groq API -> ai-agent -> app -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Oauth identity provider | Secret TWITCH_CLIENT_SECRET | Google Oauth identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Oauth identity provider | Secret PAYPAL_SECRET | Google Oauth identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Oauth identity provider | Secret MICROSOFT_CLIENT_SECRET | Google Oauth identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Oauth identity provider | Secret FOURSQUARE_APIKEY | Google Oauth identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Oauth identity provider | Secret GROQ_API_KEY | Google Oauth identity provider -> passport -> app -> ai-agent | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Oauth identity provider | Secret TUMBLR_SECRET | Google Oauth identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Oauth identity provider | Secret QUICKBOOKS_CLIENT_SECRET | Google Oauth identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Oauth identity provider | Secret GITHUB_SECRET | Google Oauth identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Oauth identity provider | Secret HERE_API_KEY | Google Oauth identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Oauth identity provider | Secret SMTP_PASSWORD | Google Oauth identity provider -> passport -> Unresolved HTTP target -> contact -> nodemailer | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Oauth identity provider | Secret FACEBOOK_SECRET | Google Oauth identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Oauth identity provider | Secret X_SECRET | Google Oauth identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Oauth identity provider | Secret GOOGLE_CLIENT_SECRET | Google Oauth identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Oauth identity provider | Secret GOOGLE_MAP_API_KEY | Google Oauth identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Oauth identity provider | Secret TWILIO_TOKEN | Google Oauth identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Oauth identity provider | Secret SESSION_SECRET | Google Oauth identity provider -> passport -> app | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Oauth identity provider | Secret LINKEDIN_SECRET | Google Oauth identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Oauth identity provider | Secret LASTFM_SECRET | Google Oauth identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Oauth identity provider | Secret GOOGLE_API_KEY | Google Oauth identity provider -> passport -> Unresolved HTTP target -> contact | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Oauth identity provider | Secret GIPHY_API_KEY | Google Oauth identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Oauth identity provider | Secret DISCORD_CLIENT_SECRET | Google Oauth identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: news.ycombinator.com | Secret TWITCH_CLIENT_SECRET | news.ycombinator.com -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: news.ycombinator.com | Secret PAYPAL_SECRET | news.ycombinator.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: news.ycombinator.com | Secret MICROSOFT_CLIENT_SECRET | news.ycombinator.com -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: news.ycombinator.com | Secret FOURSQUARE_APIKEY | news.ycombinator.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: news.ycombinator.com | Secret GROQ_API_KEY | news.ycombinator.com -> api -> app -> ai-agent | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: news.ycombinator.com | Secret TUMBLR_SECRET | news.ycombinator.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: news.ycombinator.com | Secret QUICKBOOKS_CLIENT_SECRET | news.ycombinator.com -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: news.ycombinator.com | Secret GITHUB_SECRET | news.ycombinator.com -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: news.ycombinator.com | Secret HERE_API_KEY | news.ycombinator.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: news.ycombinator.com | Secret SMTP_PASSWORD | news.ycombinator.com -> api -> Unresolved HTTP target -> contact -> nodemailer | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: news.ycombinator.com | Secret FACEBOOK_SECRET | news.ycombinator.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: news.ycombinator.com | Secret X_SECRET | news.ycombinator.com -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: news.ycombinator.com | Secret GOOGLE_CLIENT_SECRET | news.ycombinator.com -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: news.ycombinator.com | Secret GOOGLE_MAP_API_KEY | news.ycombinator.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: news.ycombinator.com | Secret TWILIO_TOKEN | news.ycombinator.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: news.ycombinator.com | Secret SESSION_SECRET | news.ycombinator.com -> api -> app | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: news.ycombinator.com | Secret LINKEDIN_SECRET | news.ycombinator.com -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: news.ycombinator.com | Secret LASTFM_SECRET | news.ycombinator.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: news.ycombinator.com | Secret GOOGLE_API_KEY | news.ycombinator.com -> api -> Unresolved HTTP target -> contact | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: news.ycombinator.com | Secret GIPHY_API_KEY | news.ycombinator.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: news.ycombinator.com | Secret DISCORD_CLIENT_SECRET | news.ycombinator.com -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.sandbox.paypal.com | Secret TWITCH_CLIENT_SECRET | api.sandbox.paypal.com -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.sandbox.paypal.com | Secret PAYPAL_SECRET | api.sandbox.paypal.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.sandbox.paypal.com | Secret MICROSOFT_CLIENT_SECRET | api.sandbox.paypal.com -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.sandbox.paypal.com | Secret FOURSQUARE_APIKEY | api.sandbox.paypal.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.sandbox.paypal.com | Secret GROQ_API_KEY | api.sandbox.paypal.com -> api -> app -> ai-agent | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.sandbox.paypal.com | Secret TUMBLR_SECRET | api.sandbox.paypal.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.sandbox.paypal.com | Secret QUICKBOOKS_CLIENT_SECRET | api.sandbox.paypal.com -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.sandbox.paypal.com | Secret GITHUB_SECRET | api.sandbox.paypal.com -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.sandbox.paypal.com | Secret HERE_API_KEY | api.sandbox.paypal.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.sandbox.paypal.com | Secret SMTP_PASSWORD | api.sandbox.paypal.com -> api -> Unresolved HTTP target -> contact -> nodemailer | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.sandbox.paypal.com | Secret FACEBOOK_SECRET | api.sandbox.paypal.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.sandbox.paypal.com | Secret X_SECRET | api.sandbox.paypal.com -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.sandbox.paypal.com | Secret GOOGLE_CLIENT_SECRET | api.sandbox.paypal.com -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.sandbox.paypal.com | Secret GOOGLE_MAP_API_KEY | api.sandbox.paypal.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.sandbox.paypal.com | Secret TWILIO_TOKEN | api.sandbox.paypal.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.sandbox.paypal.com | Secret SESSION_SECRET | api.sandbox.paypal.com -> api -> app | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.sandbox.paypal.com | Secret LINKEDIN_SECRET | api.sandbox.paypal.com -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.sandbox.paypal.com | Secret LASTFM_SECRET | api.sandbox.paypal.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.sandbox.paypal.com | Secret GOOGLE_API_KEY | api.sandbox.paypal.com -> api -> Unresolved HTTP target -> contact | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.sandbox.paypal.com | Secret GIPHY_API_KEY | api.sandbox.paypal.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.sandbox.paypal.com | Secret DISCORD_CLIENT_SECRET | api.sandbox.paypal.com -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Sheets API | Secret TWITCH_CLIENT_SECRET | Google Sheets API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Sheets API | Secret PAYPAL_SECRET | Google Sheets API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Sheets API | Secret MICROSOFT_CLIENT_SECRET | Google Sheets API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Sheets API | Secret FOURSQUARE_APIKEY | Google Sheets API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Sheets API | Secret GROQ_API_KEY | Google Sheets API -> api -> app -> ai-agent | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Sheets API | Secret TUMBLR_SECRET | Google Sheets API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Sheets API | Secret QUICKBOOKS_CLIENT_SECRET | Google Sheets API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Sheets API | Secret GITHUB_SECRET | Google Sheets API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Sheets API | Secret HERE_API_KEY | Google Sheets API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Sheets API | Secret SMTP_PASSWORD | Google Sheets API -> api -> Unresolved HTTP target -> contact -> nodemailer | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Sheets API | Secret FACEBOOK_SECRET | Google Sheets API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Sheets API | Secret X_SECRET | Google Sheets API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Sheets API | Secret GOOGLE_CLIENT_SECRET | Google Sheets API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Sheets API | Secret GOOGLE_MAP_API_KEY | Google Sheets API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Sheets API | Secret TWILIO_TOKEN | Google Sheets API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Sheets API | Secret SESSION_SECRET | Google Sheets API -> api -> app | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Sheets API | Secret LINKEDIN_SECRET | Google Sheets API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Sheets API | Secret LASTFM_SECRET | Google Sheets API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Sheets API | Secret GOOGLE_API_KEY | Google Sheets API -> api -> Unresolved HTTP target -> contact | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Sheets API | Secret GIPHY_API_KEY | Google Sheets API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Sheets API | Secret DISCORD_CLIENT_SECRET | Google Sheets API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.groq.com | Secret TWITCH_CLIENT_SECRET | api.groq.com -> ai -> app -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.groq.com | Secret PAYPAL_SECRET | api.groq.com -> ai -> app -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.groq.com | Secret MICROSOFT_CLIENT_SECRET | api.groq.com -> ai -> app -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.groq.com | Secret FOURSQUARE_APIKEY | api.groq.com -> ai -> app -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.groq.com | Secret GROQ_API_KEY | api.groq.com -> ai | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.groq.com | Secret TUMBLR_SECRET | api.groq.com -> ai -> app -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.groq.com | Secret QUICKBOOKS_CLIENT_SECRET | api.groq.com -> ai -> app -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.groq.com | Secret GITHUB_SECRET | api.groq.com -> ai -> app -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.groq.com | Secret HERE_API_KEY | api.groq.com -> ai -> app -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.groq.com | Secret SMTP_PASSWORD | api.groq.com -> ai -> app -> contact -> nodemailer | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.groq.com | Secret FACEBOOK_SECRET | api.groq.com -> ai -> app -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.groq.com | Secret X_SECRET | api.groq.com -> ai -> app -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.groq.com | Secret GOOGLE_CLIENT_SECRET | api.groq.com -> ai -> app -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.groq.com | Secret GOOGLE_MAP_API_KEY | api.groq.com -> ai -> app -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.groq.com | Secret TWILIO_TOKEN | api.groq.com -> ai -> app -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.groq.com | Secret SESSION_SECRET | api.groq.com -> ai -> app | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.groq.com | Secret LINKEDIN_SECRET | api.groq.com -> ai -> app -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.groq.com | Secret LASTFM_SECRET | api.groq.com -> ai -> app -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.groq.com | Secret GOOGLE_API_KEY | api.groq.com -> ai -> app -> contact | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.groq.com | Secret GIPHY_API_KEY | api.groq.com -> ai -> app -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.groq.com | Secret DISCORD_CLIENT_SECRET | api.groq.com -> ai -> app -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.microsoft.com | Secret TWITCH_CLIENT_SECRET | graph.microsoft.com -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.microsoft.com | Secret PAYPAL_SECRET | graph.microsoft.com -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.microsoft.com | Secret MICROSOFT_CLIENT_SECRET | graph.microsoft.com -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.microsoft.com | Secret FOURSQUARE_APIKEY | graph.microsoft.com -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.microsoft.com | Secret GROQ_API_KEY | graph.microsoft.com -> passport -> app -> ai-agent | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.microsoft.com | Secret TUMBLR_SECRET | graph.microsoft.com -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.microsoft.com | Secret QUICKBOOKS_CLIENT_SECRET | graph.microsoft.com -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.microsoft.com | Secret GITHUB_SECRET | graph.microsoft.com -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.microsoft.com | Secret HERE_API_KEY | graph.microsoft.com -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.microsoft.com | Secret SMTP_PASSWORD | graph.microsoft.com -> passport -> Unresolved HTTP target -> contact -> nodemailer | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.microsoft.com | Secret FACEBOOK_SECRET | graph.microsoft.com -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.microsoft.com | Secret X_SECRET | graph.microsoft.com -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.microsoft.com | Secret GOOGLE_CLIENT_SECRET | graph.microsoft.com -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.microsoft.com | Secret GOOGLE_MAP_API_KEY | graph.microsoft.com -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.microsoft.com | Secret TWILIO_TOKEN | graph.microsoft.com -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.microsoft.com | Secret SESSION_SECRET | graph.microsoft.com -> passport -> app | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.microsoft.com | Secret LINKEDIN_SECRET | graph.microsoft.com -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.microsoft.com | Secret LASTFM_SECRET | graph.microsoft.com -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.microsoft.com | Secret GOOGLE_API_KEY | graph.microsoft.com -> passport -> Unresolved HTTP target -> contact | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.microsoft.com | Secret GIPHY_API_KEY | graph.microsoft.com -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.microsoft.com | Secret DISCORD_CLIENT_SECRET | graph.microsoft.com -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.tumblr.com | Secret TWITCH_CLIENT_SECRET | api.tumblr.com -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.tumblr.com | Secret PAYPAL_SECRET | api.tumblr.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.tumblr.com | Secret MICROSOFT_CLIENT_SECRET | api.tumblr.com -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.tumblr.com | Secret FOURSQUARE_APIKEY | api.tumblr.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.tumblr.com | Secret GROQ_API_KEY | api.tumblr.com -> api -> app -> ai-agent | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.tumblr.com | Secret TUMBLR_SECRET | api.tumblr.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.tumblr.com | Secret QUICKBOOKS_CLIENT_SECRET | api.tumblr.com -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.tumblr.com | Secret GITHUB_SECRET | api.tumblr.com -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.tumblr.com | Secret HERE_API_KEY | api.tumblr.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.tumblr.com | Secret SMTP_PASSWORD | api.tumblr.com -> api -> Unresolved HTTP target -> contact -> nodemailer | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.tumblr.com | Secret FACEBOOK_SECRET | api.tumblr.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.tumblr.com | Secret X_SECRET | api.tumblr.com -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.tumblr.com | Secret GOOGLE_CLIENT_SECRET | api.tumblr.com -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.tumblr.com | Secret GOOGLE_MAP_API_KEY | api.tumblr.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.tumblr.com | Secret TWILIO_TOKEN | api.tumblr.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.tumblr.com | Secret SESSION_SECRET | api.tumblr.com -> api -> app | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.tumblr.com | Secret LINKEDIN_SECRET | api.tumblr.com -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.tumblr.com | Secret LASTFM_SECRET | api.tumblr.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.tumblr.com | Secret GOOGLE_API_KEY | api.tumblr.com -> api -> Unresolved HTTP target -> contact | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.tumblr.com | Secret GIPHY_API_KEY | api.tumblr.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.tumblr.com | Secret DISCORD_CLIENT_SECRET | api.tumblr.com -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Steam Openid identity provider | Secret TWITCH_CLIENT_SECRET | Steam Openid identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Steam Openid identity provider | Secret PAYPAL_SECRET | Steam Openid identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Steam Openid identity provider | Secret MICROSOFT_CLIENT_SECRET | Steam Openid identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Steam Openid identity provider | Secret FOURSQUARE_APIKEY | Steam Openid identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Steam Openid identity provider | Secret GROQ_API_KEY | Steam Openid identity provider -> passport -> app -> ai-agent | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Steam Openid identity provider | Secret TUMBLR_SECRET | Steam Openid identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Steam Openid identity provider | Secret QUICKBOOKS_CLIENT_SECRET | Steam Openid identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Steam Openid identity provider | Secret GITHUB_SECRET | Steam Openid identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Steam Openid identity provider | Secret HERE_API_KEY | Steam Openid identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Steam Openid identity provider | Secret SMTP_PASSWORD | Steam Openid identity provider -> passport -> Unresolved HTTP target -> contact -> nodemailer | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Steam Openid identity provider | Secret FACEBOOK_SECRET | Steam Openid identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Steam Openid identity provider | Secret X_SECRET | Steam Openid identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Steam Openid identity provider | Secret GOOGLE_CLIENT_SECRET | Steam Openid identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Steam Openid identity provider | Secret GOOGLE_MAP_API_KEY | Steam Openid identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Steam Openid identity provider | Secret TWILIO_TOKEN | Steam Openid identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Steam Openid identity provider | Secret SESSION_SECRET | Steam Openid identity provider -> passport -> app | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Steam Openid identity provider | Secret LINKEDIN_SECRET | Steam Openid identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Steam Openid identity provider | Secret LASTFM_SECRET | Steam Openid identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Steam Openid identity provider | Secret GOOGLE_API_KEY | Steam Openid identity provider -> passport -> Unresolved HTTP target -> contact | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Steam Openid identity provider | Secret GIPHY_API_KEY | Steam Openid identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Steam Openid identity provider | Secret DISCORD_CLIENT_SECRET | Steam Openid identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.linkedin.com | Secret TWITCH_CLIENT_SECRET | api.linkedin.com -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.linkedin.com | Secret PAYPAL_SECRET | api.linkedin.com -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.linkedin.com | Secret MICROSOFT_CLIENT_SECRET | api.linkedin.com -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.linkedin.com | Secret FOURSQUARE_APIKEY | api.linkedin.com -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.linkedin.com | Secret GROQ_API_KEY | api.linkedin.com -> passport -> app -> ai-agent | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.linkedin.com | Secret TUMBLR_SECRET | api.linkedin.com -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.linkedin.com | Secret QUICKBOOKS_CLIENT_SECRET | api.linkedin.com -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.linkedin.com | Secret GITHUB_SECRET | api.linkedin.com -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.linkedin.com | Secret HERE_API_KEY | api.linkedin.com -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.linkedin.com | Secret SMTP_PASSWORD | api.linkedin.com -> passport -> Unresolved HTTP target -> contact -> nodemailer | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.linkedin.com | Secret FACEBOOK_SECRET | api.linkedin.com -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.linkedin.com | Secret X_SECRET | api.linkedin.com -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.linkedin.com | Secret GOOGLE_CLIENT_SECRET | api.linkedin.com -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.linkedin.com | Secret GOOGLE_MAP_API_KEY | api.linkedin.com -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.linkedin.com | Secret TWILIO_TOKEN | api.linkedin.com -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.linkedin.com | Secret SESSION_SECRET | api.linkedin.com -> passport -> app | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.linkedin.com | Secret LINKEDIN_SECRET | api.linkedin.com -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.linkedin.com | Secret LASTFM_SECRET | api.linkedin.com -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.linkedin.com | Secret GOOGLE_API_KEY | api.linkedin.com -> passport -> Unresolved HTTP target -> contact | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.linkedin.com | Secret GIPHY_API_KEY | api.linkedin.com -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.linkedin.com | Secret DISCORD_CLIENT_SECRET | api.linkedin.com -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Lob API | Secret TWITCH_CLIENT_SECRET | Lob API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Lob API | Secret PAYPAL_SECRET | Lob API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Lob API | Secret MICROSOFT_CLIENT_SECRET | Lob API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Lob API | Secret FOURSQUARE_APIKEY | Lob API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Lob API | Secret GROQ_API_KEY | Lob API -> api -> app -> ai-agent | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Lob API | Secret TUMBLR_SECRET | Lob API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Lob API | Secret QUICKBOOKS_CLIENT_SECRET | Lob API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Lob API | Secret GITHUB_SECRET | Lob API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Lob API | Secret HERE_API_KEY | Lob API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Lob API | Secret SMTP_PASSWORD | Lob API -> api -> Unresolved HTTP target -> contact -> nodemailer | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Lob API | Secret FACEBOOK_SECRET | Lob API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Lob API | Secret X_SECRET | Lob API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Lob API | Secret GOOGLE_CLIENT_SECRET | Lob API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Lob API | Secret GOOGLE_MAP_API_KEY | Lob API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Lob API | Secret TWILIO_TOKEN | Lob API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Lob API | Secret SESSION_SECRET | Lob API -> api -> app | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Lob API | Secret LINKEDIN_SECRET | Lob API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Lob API | Secret LASTFM_SECRET | Lob API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Lob API | Secret GOOGLE_API_KEY | Lob API -> api -> Unresolved HTTP target -> contact | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Lob API | Secret GIPHY_API_KEY | Lob API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Lob API | Secret DISCORD_CLIENT_SECRET | Lob API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Unresolved HTTP target | Secret TWITCH_CLIENT_SECRET | Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Unresolved HTTP target | Secret PAYPAL_SECRET | Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Unresolved HTTP target | Secret MICROSOFT_CLIENT_SECRET | Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Unresolved HTTP target | Secret FOURSQUARE_APIKEY | Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Unresolved HTTP target | Secret GROQ_API_KEY | Unresolved HTTP target -> token-revocation -> user -> ai-agent | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Unresolved HTTP target | Secret TUMBLR_SECRET | Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Unresolved HTTP target | Secret QUICKBOOKS_CLIENT_SECRET | Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Unresolved HTTP target | Secret GITHUB_SECRET | Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Unresolved HTTP target | Secret HERE_API_KEY | Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Unresolved HTTP target | Secret SMTP_PASSWORD | Unresolved HTTP target -> contact -> nodemailer | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Unresolved HTTP target | Secret FACEBOOK_SECRET | Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Unresolved HTTP target | Secret X_SECRET | Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Unresolved HTTP target | Secret GOOGLE_CLIENT_SECRET | Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Unresolved HTTP target | Secret GOOGLE_MAP_API_KEY | Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Unresolved HTTP target | Secret TWILIO_TOKEN | Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Unresolved HTTP target | Secret SESSION_SECRET | Unresolved HTTP target -> passport -> app | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Unresolved HTTP target | Secret LINKEDIN_SECRET | Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Unresolved HTTP target | Secret LASTFM_SECRET | Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Unresolved HTTP target | Secret GOOGLE_API_KEY | Unresolved HTTP target -> contact | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Unresolved HTTP target | Secret GIPHY_API_KEY | Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Unresolved HTTP target | Secret DISCORD_CLIENT_SECRET | Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Facebook identity provider | Secret TWITCH_CLIENT_SECRET | Facebook identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Facebook identity provider | Secret PAYPAL_SECRET | Facebook identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Facebook identity provider | Secret MICROSOFT_CLIENT_SECRET | Facebook identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Facebook identity provider | Secret FOURSQUARE_APIKEY | Facebook identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Facebook identity provider | Secret GROQ_API_KEY | Facebook identity provider -> passport -> app -> ai-agent | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Facebook identity provider | Secret TUMBLR_SECRET | Facebook identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Facebook identity provider | Secret QUICKBOOKS_CLIENT_SECRET | Facebook identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Facebook identity provider | Secret GITHUB_SECRET | Facebook identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Facebook identity provider | Secret HERE_API_KEY | Facebook identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Facebook identity provider | Secret SMTP_PASSWORD | Facebook identity provider -> passport -> Unresolved HTTP target -> contact -> nodemailer | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Facebook identity provider | Secret FACEBOOK_SECRET | Facebook identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Facebook identity provider | Secret X_SECRET | Facebook identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Facebook identity provider | Secret GOOGLE_CLIENT_SECRET | Facebook identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Facebook identity provider | Secret GOOGLE_MAP_API_KEY | Facebook identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Facebook identity provider | Secret TWILIO_TOKEN | Facebook identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Facebook identity provider | Secret SESSION_SECRET | Facebook identity provider -> passport -> app | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Facebook identity provider | Secret LINKEDIN_SECRET | Facebook identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Facebook identity provider | Secret LASTFM_SECRET | Facebook identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Facebook identity provider | Secret GOOGLE_API_KEY | Facebook identity provider -> passport -> Unresolved HTTP target -> contact | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Facebook identity provider | Secret GIPHY_API_KEY | Facebook identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Facebook identity provider | Secret DISCORD_CLIENT_SECRET | Facebook identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Stripe API | Secret TWITCH_CLIENT_SECRET | Stripe API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Stripe API | Secret PAYPAL_SECRET | Stripe API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Stripe API | Secret MICROSOFT_CLIENT_SECRET | Stripe API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Stripe API | Secret FOURSQUARE_APIKEY | Stripe API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Stripe API | Secret GROQ_API_KEY | Stripe API -> api -> app -> ai-agent | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Stripe API | Secret TUMBLR_SECRET | Stripe API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Stripe API | Secret QUICKBOOKS_CLIENT_SECRET | Stripe API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Stripe API | Secret GITHUB_SECRET | Stripe API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Stripe API | Secret HERE_API_KEY | Stripe API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Stripe API | Secret SMTP_PASSWORD | Stripe API -> api -> Unresolved HTTP target -> contact -> nodemailer | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Stripe API | Secret FACEBOOK_SECRET | Stripe API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Stripe API | Secret X_SECRET | Stripe API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Stripe API | Secret GOOGLE_CLIENT_SECRET | Stripe API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Stripe API | Secret GOOGLE_MAP_API_KEY | Stripe API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Stripe API | Secret TWILIO_TOKEN | Stripe API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Stripe API | Secret SESSION_SECRET | Stripe API -> api -> app | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Stripe API | Secret LINKEDIN_SECRET | Stripe API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Stripe API | Secret LASTFM_SECRET | Stripe API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Stripe API | Secret GOOGLE_API_KEY | Stripe API -> api -> Unresolved HTTP target -> contact | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Stripe API | Secret GIPHY_API_KEY | Stripe API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Stripe API | Secret DISCORD_CLIENT_SECRET | Stripe API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Drive API | Secret TWITCH_CLIENT_SECRET | Google Drive API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Drive API | Secret PAYPAL_SECRET | Google Drive API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Drive API | Secret MICROSOFT_CLIENT_SECRET | Google Drive API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Drive API | Secret FOURSQUARE_APIKEY | Google Drive API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Drive API | Secret GROQ_API_KEY | Google Drive API -> api -> app -> ai-agent | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Drive API | Secret TUMBLR_SECRET | Google Drive API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Drive API | Secret QUICKBOOKS_CLIENT_SECRET | Google Drive API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Drive API | Secret GITHUB_SECRET | Google Drive API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Drive API | Secret HERE_API_KEY | Google Drive API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Drive API | Secret SMTP_PASSWORD | Google Drive API -> api -> Unresolved HTTP target -> contact -> nodemailer | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Drive API | Secret FACEBOOK_SECRET | Google Drive API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Drive API | Secret X_SECRET | Google Drive API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Drive API | Secret GOOGLE_CLIENT_SECRET | Google Drive API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Drive API | Secret GOOGLE_MAP_API_KEY | Google Drive API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Drive API | Secret TWILIO_TOKEN | Google Drive API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Drive API | Secret SESSION_SECRET | Google Drive API -> api -> app | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Drive API | Secret LINKEDIN_SECRET | Google Drive API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Drive API | Secret LASTFM_SECRET | Google Drive API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Drive API | Secret GOOGLE_API_KEY | Google Drive API -> api -> Unresolved HTTP target -> contact | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Drive API | Secret GIPHY_API_KEY | Google Drive API -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Google Drive API | Secret DISCORD_CLIENT_SECRET | Google Drive API -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret TWITCH_CLIENT_SECRET | token-revocation -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret PAYPAL_SECRET | GET /api/steam handler -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret MICROSOFT_CLIENT_SECRET | token-revocation -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret FOURSQUARE_APIKEY | GET /api/steam handler -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret GROQ_API_KEY | ai-agent (inside) | none | none | agent starts at the asset holder: no control can apply |
| Insider with access to repository: hackathon-starter | Secret TUMBLR_SECRET | token-revocation -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret QUICKBOOKS_CLIENT_SECRET | token-revocation -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret GITHUB_SECRET | token-revocation -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret HERE_API_KEY | GET /api/steam handler -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret SMTP_PASSWORD | token-revocation -> user -> nodemailer | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret FACEBOOK_SECRET | token-revocation -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret X_SECRET | token-revocation -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret GOOGLE_CLIENT_SECRET | token-revocation -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret GOOGLE_MAP_API_KEY | GET /api/steam handler -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret TWILIO_TOKEN | GET /api/steam handler -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret SESSION_SECRET | ai-agent -> app | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret LINKEDIN_SECRET | token-revocation -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret LASTFM_SECRET | GET /api/steam handler -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret GOOGLE_API_KEY | POST /contact handler -> contact | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret GIPHY_API_KEY | GET /api/steam handler -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Insider with access to repository: hackathon-starter | Secret DISCORD_CLIENT_SECRET | token-revocation -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.facebook.com | Secret TWITCH_CLIENT_SECRET | graph.facebook.com -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.facebook.com | Secret PAYPAL_SECRET | graph.facebook.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.facebook.com | Secret MICROSOFT_CLIENT_SECRET | graph.facebook.com -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.facebook.com | Secret FOURSQUARE_APIKEY | graph.facebook.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.facebook.com | Secret GROQ_API_KEY | graph.facebook.com -> api -> app -> ai-agent | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.facebook.com | Secret TUMBLR_SECRET | graph.facebook.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.facebook.com | Secret QUICKBOOKS_CLIENT_SECRET | graph.facebook.com -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.facebook.com | Secret GITHUB_SECRET | graph.facebook.com -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.facebook.com | Secret HERE_API_KEY | graph.facebook.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.facebook.com | Secret SMTP_PASSWORD | graph.facebook.com -> api -> Unresolved HTTP target -> contact -> nodemailer | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.facebook.com | Secret FACEBOOK_SECRET | graph.facebook.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.facebook.com | Secret X_SECRET | graph.facebook.com -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.facebook.com | Secret GOOGLE_CLIENT_SECRET | graph.facebook.com -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.facebook.com | Secret GOOGLE_MAP_API_KEY | graph.facebook.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.facebook.com | Secret TWILIO_TOKEN | graph.facebook.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.facebook.com | Secret SESSION_SECRET | graph.facebook.com -> api -> app | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.facebook.com | Secret LINKEDIN_SECRET | graph.facebook.com -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.facebook.com | Secret LASTFM_SECRET | graph.facebook.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.facebook.com | Secret GOOGLE_API_KEY | graph.facebook.com -> api -> Unresolved HTTP target -> contact | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.facebook.com | Secret GIPHY_API_KEY | graph.facebook.com -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: graph.facebook.com | Secret DISCORD_CLIENT_SECRET | graph.facebook.com -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Github2 identity provider | Secret TWITCH_CLIENT_SECRET | Github2 identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Github2 identity provider | Secret PAYPAL_SECRET | Github2 identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Github2 identity provider | Secret MICROSOFT_CLIENT_SECRET | Github2 identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Github2 identity provider | Secret FOURSQUARE_APIKEY | Github2 identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Github2 identity provider | Secret GROQ_API_KEY | Github2 identity provider -> passport -> app -> ai-agent | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Github2 identity provider | Secret TUMBLR_SECRET | Github2 identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Github2 identity provider | Secret QUICKBOOKS_CLIENT_SECRET | Github2 identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Github2 identity provider | Secret GITHUB_SECRET | Github2 identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Github2 identity provider | Secret HERE_API_KEY | Github2 identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Github2 identity provider | Secret SMTP_PASSWORD | Github2 identity provider -> passport -> Unresolved HTTP target -> contact -> nodemailer | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Github2 identity provider | Secret FACEBOOK_SECRET | Github2 identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Github2 identity provider | Secret X_SECRET | Github2 identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Github2 identity provider | Secret GOOGLE_CLIENT_SECRET | Github2 identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Github2 identity provider | Secret GOOGLE_MAP_API_KEY | Github2 identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Github2 identity provider | Secret TWILIO_TOKEN | Github2 identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Github2 identity provider | Secret SESSION_SECRET | Github2 identity provider -> passport -> app | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Github2 identity provider | Secret LINKEDIN_SECRET | Github2 identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Github2 identity provider | Secret LASTFM_SECRET | Github2 identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Github2 identity provider | Secret GOOGLE_API_KEY | Github2 identity provider -> passport -> Unresolved HTTP target -> contact | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Github2 identity provider | Secret GIPHY_API_KEY | Github2 identity provider -> passport -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Github2 identity provider | Secret DISCORD_CLIENT_SECRET | Github2 identity provider -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: SMTP mail relay | Secret TWITCH_CLIENT_SECRET | SMTP mail relay -> contact -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: SMTP mail relay | Secret PAYPAL_SECRET | SMTP mail relay -> contact -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: SMTP mail relay | Secret MICROSOFT_CLIENT_SECRET | SMTP mail relay -> contact -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: SMTP mail relay | Secret FOURSQUARE_APIKEY | SMTP mail relay -> contact -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: SMTP mail relay | Secret GROQ_API_KEY | SMTP mail relay -> user -> ai-agent | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: SMTP mail relay | Secret TUMBLR_SECRET | SMTP mail relay -> contact -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: SMTP mail relay | Secret QUICKBOOKS_CLIENT_SECRET | SMTP mail relay -> contact -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: SMTP mail relay | Secret GITHUB_SECRET | SMTP mail relay -> contact -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: SMTP mail relay | Secret HERE_API_KEY | SMTP mail relay -> contact -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: SMTP mail relay | Secret SMTP_PASSWORD | SMTP mail relay -> nodemailer | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: SMTP mail relay | Secret FACEBOOK_SECRET | SMTP mail relay -> contact -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: SMTP mail relay | Secret X_SECRET | SMTP mail relay -> contact -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: SMTP mail relay | Secret GOOGLE_CLIENT_SECRET | SMTP mail relay -> contact -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: SMTP mail relay | Secret GOOGLE_MAP_API_KEY | SMTP mail relay -> contact -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: SMTP mail relay | Secret TWILIO_TOKEN | SMTP mail relay -> contact -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: SMTP mail relay | Secret SESSION_SECRET | SMTP mail relay -> contact -> app | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: SMTP mail relay | Secret LINKEDIN_SECRET | SMTP mail relay -> contact -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: SMTP mail relay | Secret LASTFM_SECRET | SMTP mail relay -> contact -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: SMTP mail relay | Secret GOOGLE_API_KEY | SMTP mail relay -> contact | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: SMTP mail relay | Secret GIPHY_API_KEY | SMTP mail relay -> contact -> Unresolved HTTP target -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: SMTP mail relay | Secret DISCORD_CLIENT_SECRET | SMTP mail relay -> contact -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.twitch.tv | Secret TWITCH_CLIENT_SECRET | api.twitch.tv -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.twitch.tv | Secret PAYPAL_SECRET | api.twitch.tv -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.twitch.tv | Secret MICROSOFT_CLIENT_SECRET | api.twitch.tv -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.twitch.tv | Secret FOURSQUARE_APIKEY | api.twitch.tv -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.twitch.tv | Secret GROQ_API_KEY | api.twitch.tv -> api -> app -> ai-agent | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.twitch.tv | Secret TUMBLR_SECRET | api.twitch.tv -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.twitch.tv | Secret QUICKBOOKS_CLIENT_SECRET | api.twitch.tv -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.twitch.tv | Secret GITHUB_SECRET | api.twitch.tv -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.twitch.tv | Secret HERE_API_KEY | api.twitch.tv -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.twitch.tv | Secret SMTP_PASSWORD | api.twitch.tv -> api -> Unresolved HTTP target -> contact -> nodemailer | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.twitch.tv | Secret FACEBOOK_SECRET | api.twitch.tv -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.twitch.tv | Secret X_SECRET | api.twitch.tv -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.twitch.tv | Secret GOOGLE_CLIENT_SECRET | api.twitch.tv -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.twitch.tv | Secret GOOGLE_MAP_API_KEY | api.twitch.tv -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.twitch.tv | Secret TWILIO_TOKEN | api.twitch.tv -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.twitch.tv | Secret SESSION_SECRET | api.twitch.tv -> api -> app | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.twitch.tv | Secret LINKEDIN_SECRET | api.twitch.tv -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.twitch.tv | Secret LASTFM_SECRET | api.twitch.tv -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.twitch.tv | Secret GOOGLE_API_KEY | api.twitch.tv -> api -> Unresolved HTTP target -> contact | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.twitch.tv | Secret GIPHY_API_KEY | api.twitch.tv -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: api.twitch.tv | Secret DISCORD_CLIENT_SECRET | api.twitch.tv -> api -> Unresolved HTTP target -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Hugging Face Inference API | Secret TWITCH_CLIENT_SECRET | Hugging Face Inference API -> ai -> app -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Hugging Face Inference API | Secret PAYPAL_SECRET | Hugging Face Inference API -> ai -> app -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Hugging Face Inference API | Secret MICROSOFT_CLIENT_SECRET | Hugging Face Inference API -> ai -> app -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Hugging Face Inference API | Secret FOURSQUARE_APIKEY | Hugging Face Inference API -> ai -> app -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Hugging Face Inference API | Secret GROQ_API_KEY | Hugging Face Inference API -> ai | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Hugging Face Inference API | Secret TUMBLR_SECRET | Hugging Face Inference API -> ai -> app -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Hugging Face Inference API | Secret QUICKBOOKS_CLIENT_SECRET | Hugging Face Inference API -> ai -> app -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Hugging Face Inference API | Secret GITHUB_SECRET | Hugging Face Inference API -> ai -> app -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Hugging Face Inference API | Secret HERE_API_KEY | Hugging Face Inference API -> ai -> app -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Hugging Face Inference API | Secret SMTP_PASSWORD | Hugging Face Inference API -> ai -> app -> contact -> nodemailer | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Hugging Face Inference API | Secret FACEBOOK_SECRET | Hugging Face Inference API -> ai -> app -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Hugging Face Inference API | Secret X_SECRET | Hugging Face Inference API -> ai -> app -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Hugging Face Inference API | Secret GOOGLE_CLIENT_SECRET | Hugging Face Inference API -> ai -> app -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Hugging Face Inference API | Secret GOOGLE_MAP_API_KEY | Hugging Face Inference API -> ai -> app -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Hugging Face Inference API | Secret TWILIO_TOKEN | Hugging Face Inference API -> ai -> app -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Hugging Face Inference API | Secret SESSION_SECRET | Hugging Face Inference API -> ai -> app | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Hugging Face Inference API | Secret LINKEDIN_SECRET | Hugging Face Inference API -> ai -> app -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Hugging Face Inference API | Secret LASTFM_SECRET | Hugging Face Inference API -> ai -> app -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Hugging Face Inference API | Secret GOOGLE_API_KEY | Hugging Face Inference API -> ai -> app -> contact | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Hugging Face Inference API | Secret GIPHY_API_KEY | Hugging Face Inference API -> ai -> app -> api | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Compromised third party: Hugging Face Inference API | Secret DISCORD_CLIENT_SECRET | Hugging Face Inference API -> ai -> app -> passport | none | none | NO EFFECTIVE CONTROL on the path: potential attack path |
| Anonymous HTTP caller | Secret TWITCH_CLIENT_SECRET | HTTP client -> POST /account/webauthn/verify handler -> webauthn -> User -> passport | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> POST /account/webauthn/verify handler: unknown encryption |
| Anonymous HTTP caller | Secret PAYPAL_SECRET | HTTP client -> GET /api/steam handler -> api | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> GET /api/steam handler: unknown encryption |
| Anonymous HTTP caller | Secret MICROSOFT_CLIENT_SECRET | HTTP client -> POST /account/webauthn/verify handler -> webauthn -> User -> passport | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> POST /account/webauthn/verify handler: unknown encryption |
| Anonymous HTTP caller | Secret FOURSQUARE_APIKEY | HTTP client -> GET /api/steam handler -> api | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> GET /api/steam handler: unknown encryption |
| Anonymous HTTP caller | Secret GROQ_API_KEY | HTTP client -> POST /ai/llm-classifier handler -> ai | limiter, lusca.xframe, lusca.xssProtection, morganLogger | limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> POST /ai/llm-classifier handler: unknown encryption |
| Anonymous HTTP caller | Secret TUMBLR_SECRET | HTTP client -> GET /api/steam handler -> api | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> GET /api/steam handler: unknown encryption |
| Anonymous HTTP caller | Secret QUICKBOOKS_CLIENT_SECRET | HTTP client -> POST /account/webauthn/verify handler -> webauthn -> User -> passport | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> POST /account/webauthn/verify handler: unknown encryption |
| Anonymous HTTP caller | Secret GITHUB_SECRET | HTTP client -> POST /account/webauthn/verify handler -> webauthn -> User -> passport | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> POST /account/webauthn/verify handler: unknown encryption |
| Anonymous HTTP caller | Secret HERE_API_KEY | HTTP client -> GET /api/steam handler -> api | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> GET /api/steam handler: unknown encryption |
| Anonymous HTTP caller | Secret SMTP_PASSWORD | HTTP client -> GET /login handler -> user -> nodemailer | limiter, lusca.xframe, lusca.xssProtection, morganLogger | limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> GET /login handler: unknown encryption |
| Anonymous HTTP caller | Secret FACEBOOK_SECRET | HTTP client -> GET /api/steam handler -> api | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> GET /api/steam handler: unknown encryption |
| Anonymous HTTP caller | Secret X_SECRET | HTTP client -> POST /account/webauthn/verify handler -> webauthn -> User -> passport | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> POST /account/webauthn/verify handler: unknown encryption |
| Anonymous HTTP caller | Secret GOOGLE_CLIENT_SECRET | HTTP client -> POST /account/webauthn/verify handler -> webauthn -> User -> passport | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> POST /account/webauthn/verify handler: unknown encryption |
| Anonymous HTTP caller | Secret GOOGLE_MAP_API_KEY | HTTP client -> GET /api/steam handler -> api | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> GET /api/steam handler: unknown encryption |
| Anonymous HTTP caller | Secret TWILIO_TOKEN | HTTP client -> GET /api/steam handler -> api | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> GET /api/steam handler: unknown encryption |
| Anonymous HTTP caller | Secret SESSION_SECRET | HTTP client -> POST /account/webauthn/verify handler -> webauthn -> app | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> POST /account/webauthn/verify handler: unknown encryption |
| Anonymous HTTP caller | Secret LINKEDIN_SECRET | HTTP client -> POST /account/webauthn/verify handler -> webauthn -> User -> passport | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> POST /account/webauthn/verify handler: unknown encryption |
| Anonymous HTTP caller | Secret LASTFM_SECRET | HTTP client -> GET /api/steam handler -> api | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> GET /api/steam handler: unknown encryption |
| Anonymous HTTP caller | Secret GOOGLE_API_KEY | HTTP client -> POST /contact handler -> contact | limiter, lusca.xframe, lusca.xssProtection, morganLogger | limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> POST /contact handler: unknown encryption |
| Anonymous HTTP caller | Secret GIPHY_API_KEY | HTTP client -> GET /api/steam handler -> api | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> GET /api/steam handler: unknown encryption |
| Anonymous HTTP caller | Secret DISCORD_CLIENT_SECRET | HTTP client -> POST /account/webauthn/verify handler -> webauthn -> User -> passport | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> POST /account/webauthn/verify handler: unknown encryption |
| Authenticated HTTP caller | Secret TWITCH_CLIENT_SECRET | HTTP client -> POST /account/webauthn/verify handler -> webauthn -> User -> passport | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> POST /account/webauthn/verify handler: unknown encryption |
| Authenticated HTTP caller | Secret PAYPAL_SECRET | HTTP client -> GET /api/steam handler -> api | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> GET /api/steam handler: unknown encryption |
| Authenticated HTTP caller | Secret MICROSOFT_CLIENT_SECRET | HTTP client -> POST /account/webauthn/verify handler -> webauthn -> User -> passport | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> POST /account/webauthn/verify handler: unknown encryption |
| Authenticated HTTP caller | Secret FOURSQUARE_APIKEY | HTTP client -> GET /api/steam handler -> api | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> GET /api/steam handler: unknown encryption |
| Authenticated HTTP caller | Secret GROQ_API_KEY | HTTP client -> POST /ai/llm-classifier handler -> ai | limiter, lusca.xframe, lusca.xssProtection, morganLogger | limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> POST /ai/llm-classifier handler: unknown encryption |
| Authenticated HTTP caller | Secret TUMBLR_SECRET | HTTP client -> GET /api/steam handler -> api | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> GET /api/steam handler: unknown encryption |
| Authenticated HTTP caller | Secret QUICKBOOKS_CLIENT_SECRET | HTTP client -> POST /account/webauthn/verify handler -> webauthn -> User -> passport | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> POST /account/webauthn/verify handler: unknown encryption |
| Authenticated HTTP caller | Secret GITHUB_SECRET | HTTP client -> POST /account/webauthn/verify handler -> webauthn -> User -> passport | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> POST /account/webauthn/verify handler: unknown encryption |
| Authenticated HTTP caller | Secret HERE_API_KEY | HTTP client -> GET /api/steam handler -> api | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> GET /api/steam handler: unknown encryption |
| Authenticated HTTP caller | Secret SMTP_PASSWORD | HTTP client -> GET /login handler -> user -> nodemailer | limiter, lusca.xframe, lusca.xssProtection, morganLogger | limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> GET /login handler: unknown encryption |
| Authenticated HTTP caller | Secret FACEBOOK_SECRET | HTTP client -> GET /api/steam handler -> api | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> GET /api/steam handler: unknown encryption |
| Authenticated HTTP caller | Secret X_SECRET | HTTP client -> POST /account/webauthn/verify handler -> webauthn -> User -> passport | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> POST /account/webauthn/verify handler: unknown encryption |
| Authenticated HTTP caller | Secret GOOGLE_CLIENT_SECRET | HTTP client -> POST /account/webauthn/verify handler -> webauthn -> User -> passport | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> POST /account/webauthn/verify handler: unknown encryption |
| Authenticated HTTP caller | Secret GOOGLE_MAP_API_KEY | HTTP client -> GET /api/steam handler -> api | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> GET /api/steam handler: unknown encryption |
| Authenticated HTTP caller | Secret TWILIO_TOKEN | HTTP client -> GET /api/steam handler -> api | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> GET /api/steam handler: unknown encryption |
| Authenticated HTTP caller | Secret SESSION_SECRET | HTTP client -> POST /account/webauthn/verify handler -> webauthn -> app | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> POST /account/webauthn/verify handler: unknown encryption |
| Authenticated HTTP caller | Secret LINKEDIN_SECRET | HTTP client -> POST /account/webauthn/verify handler -> webauthn -> User -> passport | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> POST /account/webauthn/verify handler: unknown encryption |
| Authenticated HTTP caller | Secret LASTFM_SECRET | HTTP client -> GET /api/steam handler -> api | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> GET /api/steam handler: unknown encryption |
| Authenticated HTTP caller | Secret GOOGLE_API_KEY | HTTP client -> POST /contact handler -> contact | limiter, lusca.xframe, lusca.xssProtection, morganLogger | limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> POST /contact handler: unknown encryption |
| Authenticated HTTP caller | Secret GIPHY_API_KEY | HTTP client -> GET /api/steam handler -> api | passportConfig.isAuthenticated, passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | passportConfig.isAuthorized, limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> GET /api/steam handler: unknown encryption |
| Authenticated HTTP caller | Secret DISCORD_CLIENT_SECRET | HTTP client -> POST /account/webauthn/verify handler -> webauthn -> User -> passport | passportConfig.isAuthenticated, limiter, lusca.xframe, lusca.xssProtection, morganLogger | limiter, lusca.xframe, lusca.xssProtection, morganLogger | controlled at entry; HTTP client -> POST /account/webauthn/verify handler: unknown encryption |

## Threat agent profiles

| Agent | Access | Location | Starts at | Passes | Goals | Origin |
|---|---|---|---|---|---|---|
| Compromised third party: Oauth2 Refresh identity provider | third_party | outside all boundaries | Oauth2 Refresh identity provider | - | return malicious responses; harvest data sent to it | inferred |
| Compromised third party: discord.com | third_party | outside all boundaries | discord.com | - | return malicious responses; harvest data sent to it | inferred |
| Compromised third party: Oauth1 identity provider | third_party | outside all boundaries | Oauth1 identity provider | - | return malicious responses; harvest data sent to it | inferred |
| Compromised third party: GitHub API | third_party | outside all boundaries | GitHub API | - | return malicious responses; harvest data sent to it | inferred |
| Compromised third party: Twilio API | third_party | outside all boundaries | Twilio API | - | return malicious responses; harvest data sent to it | inferred |
| Compromised third party: Last.fm API | third_party | outside all boundaries | Last.fm API | - | return malicious responses; harvest data sent to it | inferred |
| Compromised third party: pubchem.ncbi.nlm.nih.gov | third_party | outside all boundaries | pubchem.ncbi.nlm.nih.gov | - | return malicious responses; harvest data sent to it | inferred |
| Compromised third party: Groq API | third_party | outside all boundaries | Groq API | - | return malicious responses; harvest data sent to it | inferred |
| Compromised third party: Google Oauth identity provider | third_party | outside all boundaries | Google Oauth identity provider | - | return malicious responses; harvest data sent to it | inferred |
| Compromised third party: news.ycombinator.com | third_party | outside all boundaries | news.ycombinator.com | - | return malicious responses; harvest data sent to it | inferred |
| Compromised third party: api.sandbox.paypal.com | third_party | outside all boundaries | api.sandbox.paypal.com | - | return malicious responses; harvest data sent to it | inferred |
| Compromised third party: Google Sheets API | third_party | outside all boundaries | Google Sheets API | - | return malicious responses; harvest data sent to it | inferred |
| Compromised third party: api.groq.com | third_party | outside all boundaries | api.groq.com | - | return malicious responses; harvest data sent to it | inferred |
| Compromised third party: graph.microsoft.com | third_party | outside all boundaries | graph.microsoft.com | - | return malicious responses; harvest data sent to it | inferred |
| Compromised third party: api.tumblr.com | third_party | outside all boundaries | api.tumblr.com | - | return malicious responses; harvest data sent to it | inferred |
| Anonymous HTTP caller | anonymous | outside all boundaries | HTTP client | - | reach data or functions without authenticating | inferred |
| Compromised third party: Steam Openid identity provider | third_party | outside all boundaries | Steam Openid identity provider | - | return malicious responses; harvest data sent to it | inferred |
| Compromised third party: api.linkedin.com | third_party | outside all boundaries | api.linkedin.com | - | return malicious responses; harvest data sent to it | inferred |
| Compromised third party: Lob API | third_party | outside all boundaries | Lob API | - | return malicious responses; harvest data sent to it | inferred |
| Compromised third party: Unresolved HTTP target | third_party | outside all boundaries | Unresolved HTTP target | - | return malicious responses; harvest data sent to it | inferred |
| Compromised third party: Facebook identity provider | third_party | outside all boundaries | Facebook identity provider | - | return malicious responses; harvest data sent to it | inferred |
| Compromised third party: Stripe API | third_party | outside all boundaries | Stripe API | - | return malicious responses; harvest data sent to it | inferred |
| Compromised third party: Google Drive API | third_party | outside all boundaries | Google Drive API | - | return malicious responses; harvest data sent to it | inferred |
| Authenticated HTTP caller | authenticated | outside all boundaries | HTTP client | authn | access other users' data; abuse privileged functions | inferred |
| Insider with access to repository: hackathon-starter | insider | repository: hackathon-starter | POST /account/webauthn/verify handler, token-revocation, GET /login handler, POST /ai/llm-classifier handler, GET /api/steam handler ... | authn, authz, rate_limit, input_validation, csrf, cors | read stores directly; exfiltrate secrets | inferred |
| Compromised third party: graph.facebook.com | third_party | outside all boundaries | graph.facebook.com | - | return malicious responses; harvest data sent to it | inferred |
| Compromised third party: Github2 identity provider | third_party | outside all boundaries | Github2 identity provider | - | return malicious responses; harvest data sent to it | inferred |
| Compromised third party: SMTP mail relay | third_party | outside all boundaries | SMTP mail relay | - | return malicious responses; harvest data sent to it | inferred |
| Compromised third party: api.twitch.tv | third_party | outside all boundaries | api.twitch.tv | - | return malicious responses; harvest data sent to it | inferred |
| Compromised third party: Hugging Face Inference API | third_party | outside all boundaries | Hugging Face Inference API | - | return malicious responses; harvest data sent to it | inferred |

## Assets

| Asset | Kind | Data classes | Held by | Processed by |
|---|---|---|---|---|
| Secret TWITCH_CLIENT_SECRET | credential | secret | passport | passport |
| Secret PAYPAL_SECRET | credential | secret | api | api |
| Secret MICROSOFT_CLIENT_SECRET | credential | secret | passport | passport |
| Secret FOURSQUARE_APIKEY | credential | secret | api | api |
| Secret GROQ_API_KEY | credential | secret | ai-agent, ai | ai-agent, ai |
| Secret TUMBLR_SECRET | credential | secret | passport, api | passport, api |
| Secret QUICKBOOKS_CLIENT_SECRET | credential | secret | passport | passport |
| Secret GITHUB_SECRET | credential | secret | passport | passport |
| Secret HERE_API_KEY | credential | secret | api | api |
| Secret SMTP_PASSWORD | credential | secret | nodemailer | nodemailer |
| Secret FACEBOOK_SECRET | credential | secret | passport, api | passport, api |
| Secret X_SECRET | credential | secret | passport | passport |
| Secret GOOGLE_CLIENT_SECRET | credential | secret | passport | passport |
| Secret GOOGLE_MAP_API_KEY | credential | secret | api | api |
| Secret TWILIO_TOKEN | credential | secret | api | api |
| Secret SESSION_SECRET | credential | secret | app | app |
| Secret LINKEDIN_SECRET | credential | secret | passport | passport |
| Secret LASTFM_SECRET | credential | secret | api | api |
| Secret GOOGLE_API_KEY | credential | secret | contact | contact |
| Secret GIPHY_API_KEY | credential | secret | api | api |
| Secret DISCORD_CLIENT_SECRET | credential | secret | passport | passport |
