class AuthenticationController < ApplicationController
    before_action :authorize_request, except: :login
  
    # POST /register
    def register
      @user = User.new(user_params)
      if @user.save
        render json: { user: @user, token: encode_token(@user.id) }, status: :created
      else
        render json: { errors: @user.errors.full_messages }, status: :unprocessable_entity
      end
    end
  
    # POST /login
    def login
      @user = User.find_by(email: params[:email])
      if @user&.authenticate(params[:password])
        render json: { token: encode_token(@user.id), user: @user }, status: :ok
      else
        render json: { error: 'Invalid credentials' }, status: :unauthorized
      end
    end
  
    private
  
    def user_params
      params.permit(:name, :email, :password, :password_confirmation)
    end
  
    # JWT encode
    def encode_token(user_id)
      JWT.encode({ user_id: user_id, exp: 24.hours.from_now.to_i }, Rails.application.secrets.secret_key_base)
    end
  end  
