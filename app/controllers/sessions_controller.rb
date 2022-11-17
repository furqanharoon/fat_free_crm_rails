# frozen_string_literal: true

# Copyright (c) 2008-2013 Michael Dvorkin and contributors.
#
# Fat Free CRM is freely distributable under the terms of MIT license.
# See MIT-LICENSE file or http://www.opensource.org/licenses/mit-license.php
#------------------------------------------------------------------------------
class SessionsController < Devise::SessionsController
  respond_to :html
  append_view_path 'app/views/devise'

  def create
    @user = User.find_by_email(params[:user][:email])
    @user = User.find_by_username(params[:user][:username])
    
    if @user && @user.valid_password?(params[:user][:password])
      session[:user_id] = @user.id
      flash[:notice] = "Successfully Logged In #{ @user.username }"
    end
      redirect_to root_url
  end

  def after_sign_out_path_for(*)
    new_user_session_path
  end
end
