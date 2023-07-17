rule detect_discord_token_stealer {
    meta:
        description = "Detects Discord token stealers"
    strings:
        $discord_token_identifier = "NjM" wide ascii nocase
		$require_discord_js = "require('discord.js')"
        $http_user_agent = "DiscordBot"
        $web_exfiltration = /(http|https):\/\/[^\s\/$.?#]+\S*/ nocase
    condition:
        any of ($discord_token_identifier, $http_user_agent, $require_discord_js) and $web_exfiltration
}