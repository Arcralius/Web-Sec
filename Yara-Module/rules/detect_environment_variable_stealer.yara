

rule detect_environment_variable_stealer {
    meta:
        description = "Detects environment variable stealers"
    strings:
        $environment_variables = "process.env"
        $post_method = "post" wide ascii nocase
        $web_exfiltration_url = /(http|https):\/\/[^\s\/$.?#]+\S*/ nocase
    condition:
        $environment_variables and $post_method and $web_exfiltration_url
}
