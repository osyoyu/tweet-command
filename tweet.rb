#!/usr/bin/env ruby
# encoding: UTF-8

require 'base64'
require 'openssl'
require 'net/https'
require 'cgi'


# init https connection
https = Net::HTTP.new('api.twitter.com', 443)
https.use_ssl = true
https.verify_mode = OpenSSL::SSL::VERIFY_PEER
https.ca_file = 'twitter.crt'
https.verify_depth = 5


# init OAuth
consumer_key = "bPWKEcFYwxtcJflbq2Naw"
consumer_secret = "AT0tp6fEiQmxEdVxDPa8aeXWE6FQM4e08i9jaiZBj0"
nonce = (("a".."z").to_a + ("A".."Z").to_a + (0..9).to_a).shuffle[0..7].join
timestamp = Time.now.to_i
token = ["", "", ""]


if !File.exist?(ENV["HOME"] + '/.tweet')
	# get Request Token
	param_string = "oauth_callback=oob&oauth_consumer_key=#{consumer_key}&oauth_nonce=#{nonce}&oauth_signature_method=HMAC-SHA1&oauth_timestamp=#{timestamp}&oauth_version=1.0"
	signature_base = "POST&" + CGI.escape('https://api.twitter.com/oauth/request_token') + "&" + CGI.escape(param_string)
	signing_key = consumer_secret + "&"
	signature = Base64.encode64(OpenSSL::HMAC.digest(OpenSSL::Digest::SHA1.new, signing_key, signature_base)).chomp!
	oauth_header = "OAuth oauth_callback=\"oob\", oauth_consumer_key=\"#{consumer_key}\", oauth_nonce=\"#{nonce}\", oauth_signature=\"#{CGI.escape(signature)}\", oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"#{timestamp}\", oauth_version=\"1.0\""

	https.start {
		response = https.post('/oauth/request_token', nil, {'Authorization' => oauth_header})
		r = Regexp.new('.*oauth_token=(.*)&oauth_token_secret=(.*)&.*')
		token =  r.match(response.body)

		puts "Open http://api.twitter.com/oauth/authenticate?oauth_token=#{token[1]}"	
	}

	print "Enter PIN: "
	pin = STDIN.gets.chomp


	# get OAuth Token
	param_string = "oauth_consumer_key=#{consumer_key}&oauth_nonce=#{nonce}&oauth_signature_method=HMAC-SHA1&oauth_timestamp=#{timestamp}&oauth_token=#{token[1]}&oauth_version=1.0"
	signature_base = "POST&" + CGI.escape('https://api.twitter.com/oauth/access_token') + "&" + CGI.escape(param_string)
	signing_key = consumer_secret + "&" + token[2]
	signature = Base64.encode64(OpenSSL::HMAC.digest(OpenSSL::Digest::SHA1.new, signing_key, signature_base)).chomp!
	oauth_header = "OAuth oauth_consumer_key=\"#{consumer_key}\", oauth_nonce=\"#{nonce}\", oauth_signature=\"#{CGI.escape(signature)}\", oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"#{timestamp}\", oauth_token=\"#{token[1]}\", oauth_version=\"1.0\""

	https.start {
		response = https.post('/oauth/access_token', "oauth_verifier=#{pin}", {'Authorization' => oauth_header})
		r = Regexp.new('.*oauth_token=(.*)&oauth_token_secret=(.*)&user_id=.*&.*')
		token =  r.match(response.body)

		file = open(ENV['HOME'] + '/.tweet', "w+")
		file.puts token[1]
		file.puts token[2]
		file.close
	}

	puts "\nYour auth info was saved in ~/.tweet ."
	puts "You won't have to authencate again unless you delete this file."

	exit
end

# open token file
tokenfile = open(ENV['HOME'] + '/.tweet')
tokenfile.each_with_index {|line, c|
	token[c+1] = line.chomp!
}

# read status from STDIN
status = gets.chomp!.force_encoding("UTF-8")
status[140 .. status.size] = "" 

# send to Twitter
param_string = "oauth_consumer_key=#{consumer_key}&oauth_nonce=#{nonce}&oauth_signature_method=HMAC-SHA1&oauth_timestamp=#{timestamp}&oauth_token=#{token[1]}&oauth_version=1.0&status=#{CGI.escape(status).gsub("+", "%20")}"
signature_base = "POST&" + CGI.escape('https://api.twitter.com/1/statuses/update.json') + "&" + CGI.escape(param_string)
signing_key = consumer_secret + "&" + token[2]
signature = Base64.encode64(OpenSSL::HMAC.digest(OpenSSL::Digest::SHA1.new, signing_key, signature_base)).chomp!
oauth_header = "OAuth oauth_consumer_key=\"#{consumer_key}\", oauth_nonce=\"#{nonce}\", oauth_signature=\"#{CGI.escape(signature)}\", oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"#{timestamp}\", oauth_token=\"#{token[1]}\", oauth_version=\"1.0\""

https.start {
	response = https.post('/1/statuses/update.json', "status=#{CGI.escape(status).gsub("+", "%20")}", {'Authorization' => oauth_header})
	if response.code.to_i >= 200 && response.code.to_i < 300
		STDERR.puts "Tweet succeeded."
	else
		STDERR.puts "Tweet failed - if this happens again, deleting your ~/.tweet file might work."
		STDERR.puts response.body
	end
}
