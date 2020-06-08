begin
  require "bundler/inline"
rescue LoadError => e
  $stderr.puts "Bundler version 1.10 or later is required. Please update your Bundler"
  raise e
end

gemfile(true) do
  source "https://rubygems.org"
  gem 'rails', '~> 6.0.0'
  gem 'jwt'
  gem 'bcrypt'
  gem 'faraday'
  gem 'faraday_middleware'
end

require "faraday"
require "faraday_middleware"
require "action_controller/railtie"

module Queries
  UserByEmailQuery = <<~GRAPHQL
    query ($email: String!) {
      user(where: {email: {_eq: $email}}, limit: 1) {
        id
        email
        password
      }
    }
  GRAPHQL

  CreateUserMutation = <<~GRAPHQL
    mutation ($email: String!, $password: String!) {
      insert_user_one(object: {email: $email, password: $password}) {
        id
        email
        password
      }
    }
  GRAPHQL
end

module Auth
  def Auth.hash_password(password)
    BCrypt::Password.create(password)
  end

  def Auth.compare_password(password, hashed_password)
    BCrypt::Password.new(hashed_password) == password
  end
end

class Client
  def initialize(url, headers)
    @conn = Faraday.new(url: url, headers: headers) do |c|
      c.adapter Faraday.default_adapter
      c.response :json
    end
  end

  def run_query(query, variables)
    @conn.post do |req|
      req.body = {query: query, variables: variables}.to_json
    end
  end

  def find_user_by_email(email)
    run_query(Queries::UserByEmailQuery, { email: email })
  end

  def create_user(email, password) 
    run_query(Queries::CreateUserMutation, { email: email, password: password })
  end
end

class AppController < ActionController::API
  include Auth
  @@client = Client.new("http://localhost:8080/v1/graphql",{"X-Hasura-Admin-Secret": "my-secret"})

  def signup
    values = params[:input]
    email, password = [values[:email], values[:password]]
    hashed_password = Auth.hash_password(password)
    user_request = @@client.create_user(email, hashed_password).body
    puts user_request
    render json: user_request
  end

  def login
    values = params[:input]
    email, password = [values[:email], values[:password]]
    user_request = @@client.find_user_by_email(email).body
    user = user_request.dig('data', 'user').first
    match = Auth.compare_password(password, user['password'])
    render json: if match then user else "Invalid Credentials" end
  end
end

class App < Rails::Application
  routes.append do
    post "/login" => "app#login"
    post "/signup" => "app#signup"
  end

  config.consider_all_requests_local = true # display errors
end

App.initialize!
Rack::Server.new(app: App, Port: 3000).start

