class TaskMailer < ActionMailer::Base
  def send_email_to_task_user(assign_to, user)
    I18n.locale = Setting.locale
    @assign_to = assign_to
    @user = user
    mail subject: I18n.t(:dropbox_notification_subject, subject: "Task"),
         to: @assign_to.email,
         from: @user.email,
         date: Time.now
  end
end
