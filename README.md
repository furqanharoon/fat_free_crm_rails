# Fat Free CRM [![TravisCI][travis-img-url]][travis-ci-url]  [![Code Climate][codeclimate-img-url]][codeclimate-url] [![Discord][discord-img-url]][discord-url]

[travis-img-url]: https://secure.travis-ci.org/fatfreecrm/fat_free_crm.svg?branch=master
[travis-ci-url]: https://travis-ci.org/fatfreecrm/fat_free_crm
[codeclimate-img-url]: https://codeclimate.com/github/fatfreecrm/fat_free_crm.svg
[codeclimate-url]: https://codeclimate.com/github/fatfreecrm/fat_free_crm
[discord-img-url]: https://img.shields.io/badge/chat-on%20discord-7289da.svg?sanitize=true
[discord-url]: https://discord.gg/JVrzD8RYyk
### An open source, Ruby on Rails [customer relationship management][crm-wiki] platform (CRM).

[crm-wiki]: http://en.wikipedia.org/wiki/Customer_relationship_management


Out of the box it features group collaboration, campaign and lead management,
contact lists, and opportunity tracking.

<table>
  <tr>
    <td align="center">
      <a href="https://github.com/fatfreecrm/fatfreecrm.github.com/raw/master/images/contact_create.png" target="_blank" title="Create Contacts">
        <img src="https://github.com/fatfreecrm/fatfreecrm.github.com/raw/master/images/contact_create_t.png" alt="Create Contacts">
      </a>
      <br />
      <em>Contacts</em>
    </td>
    <td align="center">
      <a href="https://github.com/fatfreecrm/fatfreecrm.github.com/raw/master/images/contact_opportunity.png" target="_blank" title="Manage Opportunities">
        <img src="https://github.com/fatfreecrm/fatfreecrm.github.com/raw/master/images/contact_opportunity_t.png" alt="Manage Opportunities">
      </a>
      <br />
      <em>Opportunities</em>
    </td>
    <td align="center">
      <a href="https://github.com/fatfreecrm/fatfreecrm.github.com/raw/master/images/account_edit.png" target="_blank" title="Edit Accounts">
        <img src="https://github.com/fatfreecrm/fatfreecrm.github.com/raw/master/images/account_edit_t.png" alt="Edit Accounts">
      </a>
      <br />
      <em>Accounts</em>
    </td>
    <td align="center">
      <a href="https://github.com/fatfreecrm/fatfreecrm.github.com/raw/master/images/task_create.png" target="_blank" title="Create Tasks">
        <img src="https://github.com/fatfreecrm/fatfreecrm.github.com/raw/master/images/task_create_t.png" alt="Create Tasks">
      </a>
      <br />
      <em>Tasks</em>
    </td>
  </tr>
</table>

Pull requests and bug reports are always welcome!

Visit our website at http://www.fatfreecrm.com/


## System Requirements

* Ruby 2.6+ recommended
* MySQL v4.1.1 or later (v5+ is recommended), SQLite v3.4 or later, or Postgres 8.4.8 or later.
* ImageMagick (optional, only needed if you would like to use avatars)

(Ruby on Rails and other gem dependencies will be installed automatically by Bundler.)


## Installation

Please view one of the following installation guides:

### [Setup Linux or Mac OS](http://guides.fatfreecrm.com/Setup-Linux-or-Mac-OS)

Installing Fat Free CRM on Linux or Mac OS X

### [Setup Heroku](http://guides.fatfreecrm.com/Setup-Heroku)

Setting up a Heroku instance for Fat Free CRM

### [Setup Microsoft Windows](http://guides.fatfreecrm.com/Setup-Microsoft-Windows)

Installing Fat Free CRM on Microsoft Windows

### [Running Fat Free CRM as a Rails Engine](http://guides.fatfreecrm.com/Running-as-a-Rails-Engine)

Run the Fat Free CRM gem within a separate Rails application.
This is the best way to deploy Fat Free CRM if you need to add plugins or make any customizations. Note that it is not yet simple to 'bolt' Fat Free CRM into your existing rails project, but we're heading in that direction.


## Upgrading from previous versions of Fat Free CRM

Please read the [Changelog](https://github.com/fatfreecrm/fat_free_crm/blob/master/CHANGELOG.md) document for more detailed information on upgrading from previous versions.


## Resources

|||
|-----------------------------------:|:--------------------------|
|                 **Home Page**: | http://www.fatfreecrm.com |
|                    **Guides**: | http://guides.fatfreecrm.com |
|       **Github Project Page**: | http://github.com/fatfreecrm/fat_free_crm |
| **Feature Requests and Bugs**: | http://support.fatfreecrm.com/ |
|                  **RDoc API**: | http://api.fatfreecrm.com |
|                  **Ruby gem**: | https://rubygems.org/gems/fat_free_crm |
|    **Twitter Commit Updates**: | http://twitter.com/fatfreecrm |
|       **User's Google Group**: | http://groups.google.com/group/fat-free-crm-users |
|  **Developer's Google Group**: | http://groups.google.com/group/fat-free-crm-dev |
|               **IRC Channel**: | [#fatfreecrm](http://webchat.freenode.net/) on irc.freenode.net |


## For Developers

Fat Free CRM is released under the MIT license and is freely available for you to use for your own purposes. We do encourage contributions to make Fat Free CRM even better. Send us a pull-request and we'll do our best to accommodate your needs.

Specific features that are not 'Fat Free' in nature, can be added by creating Rails Engines. See the [wiki](http://github.com/fatfreecrm/fat_free_crm/wiki) for information on how to do this.

Tests can easily be run by typing 'rake' but please note that they do take a while to run! Alternatively, you can see the test build status over at our [travis page](http://travis-ci.org/fatfreecrm/fat_free_crm)


## Main contributors

* [Michael Dvorkin (@michaeldv)](https://github.com/michaeldv) - Founding creator
* CloCkWeRX
* johnnyshield
* DmitryAvramec
* steveyken


See the [contributors graph](https://github.com/fatfreecrm/fat_free_crm/graphs/contributors) and the [contributors file](https://github.com/fatfreecrm/fat_free_crm/blob/master/CONTRIBUTORS.md) for further details.

## License

Fat Free CRM
Copyright (c) 2008-2018 Michael Dvorkin and contributors.

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.






















----------------------------------------------------------------------------------------
= content_for(:javascript_epilogue) do
  :plain
    document.observe("dom:loaded", function() {
      new Effect.Move("standalone", { x:0, y:-16, mode:"relative", fps:100, duration:0.15, afterFinishInternal: function(effect) {
        new Effect.Move("standalone", { x:0, y:16, mode:"relative", fps:100, duration:0.15, afterFinishInternal: function(effect) {
          new Effect.Move("standalone", { x:0, y:-8, mode:"relative", fps:100, duration:0.15, afterFinishInternal: function(effect) {
            new Effect.Move("standalone", { x:0, y:8, mode:"relative", fps:100, duration:0.15 });
          }});
        }});
      }});
    });

.standalone#standalone
  = simple_form_for(resource, as: resource_name, url: session_path(resource_name)) do |f|
    - if User.can_signup?
      .title_tools
        = t(:no_account)
        = link_to(t(:sign_up_now), new_registration_path(resource_name))
    .title= t(:login)
    .section
      .label= t(:username)
      = f.input_field :username, minlength: 1
      .label= t(:Email)
      = f.text_field :email, as: :string
      .label= t(:password)
      = f.input_field :password

    %div(style="margin-left:12px")
      = f.input :remember_me, as: :boolean, inline_label: t('remember_me')
    %br
    .buttonbar
      = f.submit t(:login)
      = t(:or)
      = link_to t(:forgot_password) + '?', new_password_path(resource_name)






*********************************Application controller*******************************************


# frozen_string_literal: true

# Copyright (c) 2008-2013 Michael Dvorkin and contributors.
#
# Fat Free CRM is freely distributable under the terms of MIT license.
# See MIT-LICENSE file or http://www.opensource.org/licenses/mit-license.php
#------------------------------------------------------------------------------
class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception

  before_action :configure_devise_parameters, if: :devise_controller?
  before_action :authenticate_user!
  before_action :set_paper_trail_whodunnit
  before_action :set_context
  before_action :clear_setting_cache
  before_action :cors_preflight_check
  before_action { hook(:app_before_filter, self) }
  after_action { hook(:app_after_filter, self) }
  after_action :cors_set_access_control_headers

  helper_method :called_from_index_page?, :called_from_landing_page?
  helper_method :klass

  respond_to :html, only: %i[index show auto_complete]
  respond_to :js
  respond_to :json, :xml, except: :edit
  respond_to :atom, :csv, :rss, :xls, only: :index

  rescue_from ActiveRecord::RecordNotFound, with: :respond_to_not_found
  rescue_from CanCan::AccessDenied,         with: :respond_to_access_denied

  include ERB::Util # to give us h and j methods

  # Common auto_complete handler for all core controllers.
  #----------------------------------------------------------------------------
  def auto_complete
    @query = params[:term] || ''
    @auto_complete = hook(:auto_complete, self, query: @query, user: current_user)
    if @auto_complete.empty?
      exclude_ids = auto_complete_ids_to_exclude(params[:related])
      @auto_complete = klass.my(current_user).text_search(@query).ransack(id_not_in: exclude_ids).result.limit(10)
    else
      @auto_complete = @auto_complete.last
    end

    session[:auto_complete] = controller_name.to_sym
    respond_to do |format|
      format.any(:js, :html) { render partial: 'auto_complete' }
      format.json do
        results = @auto_complete.map do |a|
          {
            id: a.id,
            text: a.respond_to?(:full_name) ? a.full_name : a.name
          }
        end
        render json: {
          results: results
        }
      end
    end
  end

  # To deal with pre rails 6 users, reset the session and ask them to relogin
  rescue_from ArgumentError do |exception|
    if request.format.html? && exception.message == "invalid base64"
      request.reset_session
      redirect_to login_path
    else
      raise(exception)
    end
  end

  private

  #
  # In rails 3, the default behaviour for handle_unverified_request is to delete the session
  # and continue executing the request. However, we use cookie based authentication and need
  # to halt proceedings. In Rails 4, use "protect_from_forgery with: :exception"
  # See http://blog.nvisium.com/2014/09/understanding-protectfromforgery.html for more details.
  #----------------------------------------------------------------------------
  
  def handle_unverified_request
    raise ActionController::InvalidAuthenticityToken
  end

  #
  # Takes { related: 'campaigns/7' } or { related: '5' }
  #   and returns array of object ids that should be excluded from search
  #   assumes controller_name is a method on 'related' class that returns a collection
  #----------------------------------------------------------------------------
  def auto_complete_ids_to_exclude(related)
    return [] if related.blank?
    return [related.to_i].compact unless related.index('/')

    related_class, id = related.split('/')
    obj = related_class.classify.constantize.find_by_id(id)
    if obj&.respond_to?(controller_name)
      obj.send(controller_name).map(&:id)
    else
      []
    end
  end

  #----------------------------------------------------------------------------
  def klass
    @klass ||= controller_name.classify.constantize
  end

  #----------------------------------------------------------------------------
  def clear_setting_cache
    Setting.clear_cache!
  end

  #----------------------------------------------------------------------------
  def set_context
    Time.zone = ActiveSupport::TimeZone[session[:timezone_offset]] if session[:timezone_offset]
    if current_user.present? && (locale = current_user.preference[:locale]).present?
      I18n.locale = locale
    elsif Setting.locale.present?
      I18n.locale = Setting.locale
    end
  end

  #----------------------------------------------------------------------------
  def set_current_tab(tab = controller_name)
    @current_tab = tab
  end

  #----------------------------------------------------------------------------
  def store_location
    session[:return_to] = request.fullpath
  end

  #----------------------------------------------------------------------------
  def redirect_back_or_default(default)
    redirect_to(session[:return_to] || default)
    session[:return_to] = nil
  end

  #----------------------------------------------------------------------------
  def can_signup?
    User.can_signup?
  end

  #----------------------------------------------------------------------------
  def called_from_index_page?(controller = controller_name)
    request.referer =~ if controller != "tasks"
                         %r{/#{controller}$}
                       else
                         /tasks\?*/
                       end
  end

  #----------------------------------------------------------------------------
  def called_from_landing_page?(controller = controller_name)
    request.referer =~ %r{/#{controller}/\w+}
  end

  # Proxy current page for any of the controllers by storing it in a session.
  #----------------------------------------------------------------------------
  def current_page=(page)
    p = page.to_i
    @current_page = session[:"#{controller_name}_current_page"] = (p.zero? ? 1 : p)
  end

  #----------------------------------------------------------------------------
  def current_page
    page = params[:page] || session[:"#{controller_name}_current_page"] || 1
    @current_page = page.to_i
  end

  # Proxy current search query for any of the controllers by storing it in a session.
  #----------------------------------------------------------------------------
  def current_query=(query)
    if session[:"#{controller_name}_current_query"].to_s != query.to_s # nil.to_s == ""
      self.current_page = params[:page] # reset paging otherwise results might be hidden, defaults to 1 if nil
    end
    @current_query = session[:"#{controller_name}_current_query"] = query
  end

  #----------------------------------------------------------------------------
  def current_query
    @current_query = params[:query] || session[:"#{controller_name}_current_query"] || ''
  end

  #----------------------------------------------------------------------------
  def asset
    controller_name.singularize
  end

  #----------------------------------------------------------------------------
  def respond_to_not_found(*_types)
    flash[:warning] = t(:msg_asset_not_available, asset)

    respond_to do |format|
      format.html { redirect_to(redirection_url) }
      format.js   { render plain: 'window.location.reload();' }
      format.json { render plain: flash[:warning], status: :not_found }
      format.xml  { render xml: [flash[:warning]], status: :not_found }
    end
  end

  #----------------------------------------------------------------------------
  def respond_to_related_not_found(related, *_types)
    asset = "note" if asset == "comment"
    flash[:warning] = t(:msg_cant_create_related, asset: asset, related: related)

    url = send("#{related.pluralize}_path")
    respond_to do |format|
      format.html { redirect_to(url) }
      format.js   { render plain: %(window.location.href = "#{url}";) }
      format.json { render plain: flash[:warning], status: :not_found }
      format.xml  { render xml: [flash[:warning]], status: :not_found }
    end
  end

  #----------------------------------------------------------------------------
  def respond_to_access_denied
    flash[:warning] = t(:msg_not_authorized, default: 'You are not authorized to take this action.')
    respond_to do |format|
      format.html { redirect_to(redirection_url) }
      format.js   { render plain: 'window.location.reload();' }
      format.json { render plain: flash[:warning], status: :unauthorized }
      format.xml  { render xml: [flash[:warning]], status: :unauthorized }
    end
  end

  #----------------------------------------------------------------------------
  def redirection_url
    # Try to redirect somewhere sensible. Note: not all controllers have an index action
    if current_user.present?
      respond_to?(:index) && action_name != 'index' ? { action: 'index' } : root_url
    else
      login_url
    end
  end

  def cors_set_access_control_headers
    headers['Access-Control-Allow-Origin'] = '*'
    headers['Access-Control-Allow-Methods'] = 'POST, GET, PUT, DELETE, OPTIONS'
    headers['Access-Control-Allow-Headers'] = 'Origin, Content-Type, Accept, Authorization, Token'
    headers['Access-Control-Max-Age'] = "1728000"
  end

  def cors_preflight_check
    if request.method == 'OPTIONS'
      headers['Access-Control-Allow-Origin'] = '*'
      headers['Access-Control-Allow-Methods'] = 'POST, GET, PUT, DELETE, OPTIONS'
      headers['Access-Control-Allow-Headers'] = 'X-Requested-With, X-Prototype-Version, Token'
      headers['Access-Control-Max-Age'] = '1728000'

      render plain: ''
    end
  end

  def configure_devise_parameters
    devise_parameter_sanitizer.permit(:sign_up) do |user_params|
      user_params.permit(:username, :email, :password, :password_confirmation)
    end
    
    devise_parameter_sanitizer.permit(:sign_in) do |user_params|
      user_params.permit(:username, :email)
    end
  end

  def find_class(asset)
    Rails.application.eager_load! unless Rails.application.config.cache_classes
    classes = ActiveRecord::Base.descendants.map(&:name)
    find = classes.find { |m| m == asset.classify }
    if find
      find.safe_constantize
    else
      raise "Unknown resource"
    end
  end
end




**********************************User.rb********************************************************


# frozen_string_literal: true

# Copyright (c) 2008-2013 Michael Dvorkin and contributors.
#
# Fat Free CRM is freely distributable under the terms of MIT license.
# See MIT-LICENSE file or http://www.opensource.org/licenses/mit-license.php
#------------------------------------------------------------------------------
# == Schema Information
#
# Table name: users
#
#  id                  :integer         not null, primary key
#  username            :string(32)      default(""), not null
#  email               :string(254)     default(""), not null
#  first_name          :string(32)
#  last_name           :string(32)
#  title               :string(64)
#  company             :string(64)
#  alt_email           :string(64)
#  phone               :string(32)
#  mobile              :string(32)
#  aim                 :string(32)
#  yahoo               :string(32)
#  google              :string(32)
#  skype               :string(32)
#  encrypted_password  :string(255)     default(""), not null
#  password_salt       :string(255)     default(""), not null
#  last_sign_in_at     :datetime
#  current_sign_in_at  :datetime
#  last_sign_in_ip     :string(255)
#  current_sign_in_ip  :string(255)
#  sign_in_count       :integer         default(0), not null
#  deleted_at          :datetime
#  created_at          :datetime
#  updated_at          :datetime
#  admin               :boolean         default(FALSE), not null
#  suspended_at        :datetime
#  unconfirmed_email   :string(254)     default(""), not null
#  reset_password_token    :string(255)
#  reset_password_sent_at  :datetime
#  remember_token          :string(255)
#  remember_created_at     :datetime
#  authentication_token    :string(255)
#  confirmation_token      :string(255)
#  confirmed_at            :datetime
#  confirmation_sent_at    :datetime
#

class User < ActiveRecord::Base
  devise :database_authenticatable, :registerable, :confirmable,
         :encryptable, :recoverable, :rememberable, :trackable
  before_create :suspend_if_needs_approval

  has_one :avatar, as: :entity, dependent: :destroy  # Personal avatar.
  has_many :avatars                                  # As owner who uploaded it, ex. Contact avatar.
  has_many :comments, as: :commentable               # As owner who created a comment.
  has_many :accounts
  has_many :campaigns
  has_many :leads
  has_many :contacts
  has_many :opportunities
  has_many :assigned_opportunities, class_name: 'Opportunity', foreign_key: 'assigned_to'
  has_many :permissions, dependent: :destroy
  has_many :preferences, dependent: :destroy
  has_many :lists
  has_and_belongs_to_many :groups

  has_paper_trail versions: { class_name: 'Version' }, ignore: [:last_sign_in_at]

  scope :by_id, -> { order('id DESC') }
  # TODO: /home/clockwerx/.rbenv/versions/2.5.3/lib/ruby/gems/2.5.0/gems/activerecord-5.2.3/lib/active_record/scoping/named.rb:175:in `scope': You tried to define a scope named "without" on the model "User", but ActiveRecord::Relation already defined an instance method with the same name. (ArgumentError)
  scope :without_user, ->(user) { where('id != ?', user.id).by_name }
  scope :by_name, -> { order('first_name, last_name, email') }

  scope :text_search, lambda { |query|
    query = query.gsub(/[^\w\s\-\.'\p{L}]/u, '').strip
    where('upper(username) LIKE upper(:s) OR upper(email) LIKE upper(:s) OR upper(first_name) LIKE upper(:s) OR upper(last_name) LIKE upper(:s)', s: "%#{query}%")
  }

  scope :my, ->(current_user) { accessible_by(current_user.ability) }

  scope :have_assigned_opportunities, lambda {
    joins("INNER JOIN opportunities ON users.id = opportunities.assigned_to")
      .where("opportunities.stage <> 'lost' AND opportunities.stage <> 'won'")
      .select('DISTINCT(users.id), users.*')
  }

  validates :email,
            presence: { message: :missing_email },
            length: { minimum: 3, maximum: 254 },
            uniqueness: { message: :email_in_use, case_sensitive: false },
            format: { with: /\A([^@\s]+)@((?:[-a-z0-9]+\.)+[a-z]{2,})\z/i, on: :create }
  validates :username,
            uniqueness: { message: :username_taken, case_sensitive: false },
            presence: { message: :missing_username },
            format: { with: /\A[a-z0-9_-]+\z/i }
  validates :password,
            presence: { if: :password_required? },
            confirmation: true

  #----------------------------------------------------------------------------
  def name
    first_name.blank? ? username : first_name
  end

  #----------------------------------------------------------------------------
  def full_name
    first_name.blank? && last_name.blank? ? email : "#{first_name} #{last_name}".strip
  end

  #----------------------------------------------------------------------------
  def suspended?
    suspended_at != nil
  end

  #----------------------------------------------------------------------------
  def awaits_approval?
    suspended? && sign_in_count == 0 && Setting.user_signup == :needs_approval
  end

  def active_for_authentication?
    super && confirmed? && !awaits_approval? && !suspended?
  end

  def inactive_message
    if !confirmed?
      super
    elsif awaits_approval?
      I18n.t(:msg_account_not_approved)
    elsif suspended?
      I18n.t(:msg_invalig_login)
    else
      super
    end
  end

  #----------------------------------------------------------------------------
  def preference
    @preference ||= preferences.build
  end
  alias pref preference

  # Override global I18n.locale if the user has individual local preference.
  #----------------------------------------------------------------------------
  def set_individual_locale
    I18n.locale = preference[:locale] if preference[:locale]
  end

  # Generate the value of single access token if it hasn't been set already.
  #----------------------------------------------------------------------------
  def to_json(_options = nil)
    [name].to_json
  end

  def to_xml(_options = nil)
    [name].to_xml
  end

  def password_required?
    !persisted? || !password.nil? || !password_confirmation.nil?
  end

  # Returns permissions ability object.
  #----------------------------------------------------------------------------
  def ability
    @ability ||= Ability.new(self)
  end

  # Returns true if this user is allowed to be destroyed.
  #----------------------------------------------------------------------------
  def destroyable?(current_user)
    current_user != self && !has_related_assets?
  end

  # Suspend newly created user if signup requires an approval.
  #----------------------------------------------------------------------------
  def suspend_if_needs_approval
    self.suspended_at = Time.now if Setting.user_signup == :needs_approval && !admin
  end

  # Prevent deleting a user unless she has no artifacts left.
  #----------------------------------------------------------------------------
  def has_related_assets?
    sum = %w[Account Campaign Lead Contact Opportunity Comment Task].detect do |asset|
      klass = asset.constantize

      asset != "Comment" && klass.assigned_to(self).exists? || klass.created_by(self).exists?
    end
    !sum.nil?
  end

  # Define class methods
  #----------------------------------------------------------------------------
  class << self
    def can_signup?
      %i[allowed needs_approval].include? Setting.user_signup
    end

    # Overrides Devise sign-in to use either username or email (case-insensitive)
    #----------------------------------------------------------------------------
    def find_for_database_authentication(warden_conditions)
      conditions = warden_conditions.dup
      if login = conditions.delete(:email)
        where(conditions.to_h).where(["lower(username) = :value OR lower(email) = :value", { value: login.downcase }]).first
      end
    end
  end

  ActiveSupport.run_load_hooks(:fat_free_crm_user, self)
end



**************************************Devise.rb****************************************************

# frozen_string_literal: true

# Copyright (c) 2008-2013 Michael Dvorkin and contributors.
#
# Fat Free CRM is freely distributable under the terms of MIT license.
# See MIT-LICENSE file or http://www.opensource.org/licenses/mit-license.php
#------------------------------------------------------------------------------
require 'devise-encryptable'

# Use this hook to configure devise mailer, warden hooks and so forth.
# Many of these configuration options can be set straight in your model.
Devise.setup do |config|
  # The secret key used by Devise. Devise uses this key to generate
  # random tokens. Changing this key will render invalid all existing
  # confirmation, reset password and unlock tokens in the database.
  # Devise will use the `secret_key_base` as its `secret_key`
  # by default. You can change it below and use your own secret key.
  # config.secret_key = SecureRandom.hex(64)

  # ==> Mailer Configuration
  # Configure the e-mail address which will be shown in Devise::Mailer,
  # note that it will be overwritten if you use your own mailer class
  # with default "from" parameter.
  config.mailer_sender = 'noreply@fatfreecrm.com'

  # Configure the class responsible to send e-mails.
  config.mailer = 'DeviseMailer'

  # Configure the parent class responsible to send e-mails.
  # config.parent_mailer = 'ActionMailer::Base'

  # ==> ORM configuration
  # Load and configure the ORM. Supports :active_record (default) and
  # :mongoid (bson_ext recommended) by default. Other ORMs may be
  # available as additional gems.
  require 'devise/orm/active_record'

  # ==> Configuration for any authentication mechanism
  # Configure which keys are used when authenticating a user. The default is
  # just :email. You can configure it to use [:username, :subdomain], so for
  # authenticating a user, both parameters are required. Remember that those
  # parameters are used only when authenticating and not when retrieving from
  # session. If you need permissions, you should implement that in a before filter.
  # You can also supply a hash where the value is a boolean determining whether
  # or not authentication should be aborted when the value is not present.
  #config.authentication_keys = [:email]

  # Configure parameters from the request object used for authentication. Each entry
  # given should be a request method and it will automatically be passed to the
  # find_for_authentication method and considered in your model lookup. For instance,
  # if you set :request_keys to [:subdomain], :subdomain will be used on authentication.
  # The same considerations mentioned for authentication_keys also apply to request_keys.
  # config.request_keys = []

  # Configure which authentication keys should be case-insensitive.
  # These keys will be downcased upon creating or modifying a user and when used
  # to authenticate or find a user. Default is :email.
  config.case_insensitive_keys = [:email]

  # Configure which authentication keys should have whitespace stripped.
  # These keys will have whitespace before and after removed upon creating or
  # modifying a user and when used to authenticate or find a user. Default is :email.
  config.strip_whitespace_keys = [:email]

  # Tell if authentication through request.params is enabled. True by default.
  # It can be set to an array that will enable params authentication only for the
  # given strategies, for example, `config.params_authenticatable = [:database]` will
  # enable it only for database (email + password) authentication.
  # config.params_authenticatable = true

  # Tell if authentication through HTTP Auth is enabled. False by default.
  # It can be set to an array that will enable http authentication only for the
  # given strategies, for example, `config.http_authenticatable = [:database]` will
  # enable it only for database authentication. The supported strategies are:
  # :database      = Support basic authentication with authentication key + password
  # config.http_authenticatable = false

  # If 401 status code should be returned for AJAX requests. True by default.
  # config.http_authenticatable_on_xhr = true

  # The realm used in Http Basic Authentication. 'Application' by default.
  # config.http_authentication_realm = 'Application'

  # It will change confirmation, password recovery and other workflows
  # to behave the same regardless if the e-mail provided was right or wrong.
  # Does not affect registerable.
  # config.paranoid = true

  # By default Devise will store the user in session. You can skip storage for
  # particular strategies by setting this option.
  # Notice that if you are skipping storage for all authentication paths, you
  # may want to disable generating routes to Devise's sessions controller by
  # passing skip: :sessions to `devise_for` in your config/routes.rb
  config.skip_session_storage = [:http_auth]

  # By default, Devise cleans up the CSRF token on authentication to
  # avoid CSRF token fixation attacks. This means that, when using AJAX
  # requests for sign in and sign up, you need to get a new CSRF token
  # from the server. You can disable this option at your own risk.
  # config.clean_up_csrf_token_on_authentication = true

  # When false, Devise will not attempt to reload routes on eager load.
  # This can reduce the time taken to boot the app but if your application
  # requires the Devise mappings to be loaded during boot time the application
  # won't boot properly.
  # config.reload_routes = true

  # ==> Configuration for :database_authenticatable
  # For bcrypt, this is the cost for hashing the password and defaults to 11. If
  # using other algorithms, it sets how many times you want the password to be hashed.
  #
  # Limiting the stretches to just one in testing will increase the performance of
  # your test suite dramatically. However, it is STRONGLY RECOMMENDED to not use
  # a value less than 10 in other environments. Note that, for bcrypt (the default
  # algorithm), the cost increases exponentially with the number of stretches (e.g.
  # a value of 20 is already extremely slow: approx. 60 seconds for 1 calculation).
  # config.stretches = Rails.env.test? ? 1 : 11 # SEE BELOW

  # Set up a pepper to generate the hashed password.
  # config.pepper = SecureRandom.hex(64)

  # Send a notification to the original email when the user's email is changed.
  # config.send_email_changed_notification = false

  # Send a notification email when the user's password is changed.
  # config.send_password_change_notification = false

  # ==> Configuration for :confirmable
  # A period that the user is allowed to access the website even without
  # confirming their account. For instance, if set to 2.days, the user will be
  # able to access the website for two days without confirming their account,
  # access will be blocked just in the third day. Default is 0.days, meaning
  # the user cannot access the website without confirming their account.
  # config.allow_unconfirmed_access_for = 2.days

  # A period that the user is allowed to confirm their account before their
  # token becomes invalid. For example, if set to 3.days, the user can confirm
  # their account within 3 days after the mail was sent, but on the fourth day
  # their account can't be confirmed with the token any more.
  # Default is nil, meaning there is no restriction on how long a user can take
  # before confirming their account.
  # config.confirm_within = 3.days

  # If true, requires any email changes to be confirmed (exactly the same way as
  # initial account confirmation) to be applied. Requires additional unconfirmed_email
  # db field (see migrations). Until confirmed, new email is stored in
  # unconfirmed_email column, and copied to email column on successful confirmation.
  config.reconfirmable = true

  # Defines which key will be used when confirming an account
  # config.confirmation_keys = [:email]

  # ==> Configuration for :rememberable
  # The time the user will be remembered without asking for credentials again.
  # config.remember_for = 2.weeks

  # Invalidates all the remember me tokens when the user signs out.
  config.expire_all_remember_me_on_sign_out = true

  # If true, extends the user's remember period when remembered via cookie.
  # config.extend_remember_period = false

  # Options to be passed to the created cookie. For instance, you can set
  # secure: true in order to force SSL only cookies.
  # config.rememberable_options = {}

  # ==> Configuration for :validatable
  # Range for password length.
  config.password_length = 8..128

  # Email regex used to validate email formats. It simply asserts that
  # one (and only one) @ exists in the given string. This is mainly
  # to give user feedback and not to assert the e-mail validity.
  # config.email_regexp = /\A[^@\s]+@[^@\s]+\z/

  # ==> Configuration for :timeoutable
  # The time you want to timeout the user session without activity. After this
  # time the user will be asked for credentials again. Default is 30 minutes.
  # config.timeout_in = 30.minutes

  # ==> Configuration for :lockable
  # Defines which strategy will be used to lock an account.
  # :failed_attempts = Locks an account after a number of failed attempts to sign in.
  # :none            = No lock strategy. You should handle locking by yourself.
  # config.lock_strategy = :failed_attempts

  # Defines which key will be used when locking and unlocking an account
  # config.unlock_keys = [:email]

  # Defines which strategy will be used to unlock an account.
  # :email = Sends an unlock link to the user email
  # :time  = Re-enables login after a certain amount of time (see :unlock_in below)
  # :both  = Enables both strategies
  # :none  = No unlock strategy. You should handle unlocking by yourself.
  # config.unlock_strategy = :both

  # Number of authentication tries before locking an account if lock_strategy
  # is failed attempts.
  # config.maximum_attempts = 20

  # Time interval to unlock the account if :time is enabled as unlock_strategy.
  # config.unlock_in = 1.hour

  # Warn on the last attempt before the account is locked.
  # config.last_attempt_warning = true

  # ==> Configuration for :recoverable
  #
  # Defines which key will be used when recovering the password for an account
  # config.reset_password_keys = [:email]

  # Time interval you can reset your password with a reset password key.
  # Don't put a too small interval or your users won't have the time to
  # change their passwords.
  config.reset_password_within = 6.hours

  # When set to false, does not sign a user in automatically after their password is
  # reset. Defaults to true, so a user is signed in automatically after a reset.
  # config.sign_in_after_reset_password = true

  # ==> Configuration for :encryptable
  # Allow you to use another hashing or encryption algorithm besides bcrypt (default).
  # You can use :sha1, :sha512 or algorithms from others authentication tools as
  # :clearance_sha1, :authlogic_sha512 (then you should set stretches above to 20
  # for default behavior) and :restful_authentication_sha1 (then you should set
  # stretches to 10, and copy REST_AUTH_SITE_KEY to pepper).
  #
  # Require the `devise-encryptable` gem when using anything other than bcrypt

  # Backward compatibility with Authlogic gem
  config.encryptor = :authlogic_sha512
  config.stretches = Rails.env.test? ? 1 : 20

  # ==> Scopes configuration
  # Turn scoped views on. Before rendering "sessions/new", it will first check for
  # "users/sessions/new". It's turned off by default because it's slower if you
  # are using only default views.
  # config.scoped_views = false

  # Configure the default scope given to Warden. By default it's the first
  # devise role declared in your routes (usually :user).
  # config.default_scope = :user

  # Set this configuration to false if you want /users/sign_out to sign out
  # only the current scope. By default, Devise signs out all scopes.
  # config.sign_out_all_scopes = true

  # ==> Navigation configuration
  # Lists the formats that should be treated as navigational. Formats like
  # :html, should redirect to the sign in page when the user does not have
  # access, but formats like :xml or :json, should return 401.
  #
  # If you have any extra navigational formats, like :iphone or :mobile, you
  # should add them to the navigational formats lists.
  #
  # The "*/*" below is required to match Internet Explorer requests.
  # config.navigational_formats = ['*/*', :html]

  # The default HTTP method used to sign out a resource. Default is :delete.
  config.sign_out_via = :delete

  # ==> OmniAuth
  # Add a new OmniAuth provider. Check the wiki for more information on setting
  # up on your models and hooks.
  # config.omniauth :github, 'APP_ID', 'APP_SECRET', scope: 'user,public_repo'

  # ==> Warden configuration
  # If you want to use other strategies, that are not supported by Devise, or
  # change the failure app, you can configure them inside the config.warden block.
  #
  # config.warden do |manager|
  #   manager.intercept_401 = false
  #   manager.default_strategies(scope: :user).unshift :some_external_strategy
  # end

  # ==> Mountable engine configurations
  # When using Devise inside an engine, let's call it `MyEngine`, and this engine
  # is mountable, there are some extra configurations to be taken into account.
  # The following options are available, assuming the engine is mounted as:
  #
  #     mount MyEngine, at: '/my_engine'
  #
  # The router that invoked `devise_for`, in the example above, would be:
  # config.router_name = :my_engine
  #
  # When using OmniAuth, Devise cannot automatically set OmniAuth path,
  # so you need to do it manually. For the users scope, it would be:
  # config.omniauth_path_prefix = '/my_engine/users/auth'
end
