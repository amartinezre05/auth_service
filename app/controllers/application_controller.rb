class ApplicationController < ActionController::API
    def authorize_request
        header = request.headers['Authorization']
        token = header.split(' ').last if header
        begin
            decoded = JWT.decode(token, Rails.application.secrets.secret_key_base)[0]
            @current_user = User.find(decoded["user_id"])
        rescue ActiveRecord::RecordNotFound, JWT::DecodeError
            render json: { errors: 'Unauthorized' }, status: :unauthorized
        end
    end
end
