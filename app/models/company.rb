class Company < ActiveRecord::Base
  has_many :contact_company
  has_many :contacts, through: :contact_company
end
