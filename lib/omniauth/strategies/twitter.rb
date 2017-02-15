require 'omniauth-oauth'
require 'json'

module OmniAuth
  module Strategies
    class Twitter < OmniAuth::Strategies::OAuth
      option :name, 'twitter'

      option :client_options, {:authorize_path => '/oauth/authenticate',
                               :site => 'https://api.twitter.com',
                               :proxy => ENV['http_proxy'] ? URI(ENV['http_proxy']) : nil}

      uid { access_token.params[:user_id] }

      info do
        {
          :nickname => raw_info['screen_name'],
          :name => raw_info['name'],
          :email => raw_info["email"],
          :location => raw_info['location'],
          :image => image_url,
          :description => raw_info['description'],
          :urls => {
            'Website' => raw_info['url'],
            'Twitter' => "https://twitter.com/#{raw_info['screen_name']}",
          }
        }
      end

      extra do
        skip_info? ? {} : { :raw_info => raw_info }
      end

      def raw_info
        @raw_info ||= JSON.load(access_token.get('/1.1/account/verify_credentials.json?include_entities=false&skip_status=true&include_email=true').body)
      rescue ::Errno::ETIMEDOUT
        raise ::Timeout::Error
      end
      
      def client
              ::OAuth::Consumer.new(options.client_id, options.client_secret, deep_symbolize(options.client_options))
      end
      

      alias :old_request_phase :request_phase

      def request_phase
        %w[force_login lang screen_name].each do |v|
          if request.params[v]
            options[:authorize_params][v.to_sym] = request.params[v]
          end
        end

        %w[x_auth_access_type].each do |v|
          if request.params[v]
            options[:request_params][v.to_sym] = request.params[v]
          end
        end

        if options[:use_authorize] || request.params['use_authorize'] == 'true'
          options[:client_options][:authorize_path] = '/oauth/authorize'
        else
          options[:client_options][:authorize_path] = '/oauth/authenticate'
        end

        old_request_phase
      end
      
      
      def callback_phase
        if !request.params['access_token'] || request.params['access_token'].to_s.empty?
          raise ArgumentError.new("No access token provided.")
        end
        
        if !request.params['token_secret'] || request.params['token_secret'].to_s.empty?
          raise ArgumentError.new("No token secret provided.")
        end

        self.access_token = build_access_token
        

        # TODO: Validate the token

        # Preserve compatibility with the google provider in normal case
        hash = auth_hash
        hash[:provider] = "twitter"
        self.env['omniauth.auth'] = hash
        call_app!

      rescue ::OAuth2::Error => e
        fail!(:invalid_credentials, e)
      rescue ::MultiJson::DecodeError => e
        fail!(:invalid_response, e)
      rescue ::Timeout::Error, ::Errno::ETIMEDOUT => e
        fail!(:timeout, e)
      rescue ::SocketError => e
        fail!(:failed_to_connect, e)
      end

      alias :old_callback_url :callback_url

      def callback_url
        if request.params['callback_url']
          request.params['callback_url']
        else
          old_callback_url
        end
      end

      def callback_path
        params = session['omniauth.params']

        if params.nil? || params['callback_url'].nil?
          super
        else
          URI(params['callback_url']).path
        end
      end

      private
      
      def build_access_token
              ::OAuth::AccessToken.new(
                client,
                request.params["access_token"],
                request.params["token_secret"]
              )
      end

      def image_url
        original_url = options[:secure_image_url] ? raw_info['profile_image_url_https'] : raw_info['profile_image_url']
        case options[:image_size]
        when 'mini'
          original_url.sub('normal', 'mini')
        when 'bigger'
          original_url.sub('normal', 'bigger')
        when 'original'
          original_url.sub('_normal', '')
        else
          original_url
        end
      end

    end
  end
end
