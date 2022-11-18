class AddQualificationToContacts < ActiveRecord::Migration[6.1]
  def change
    add_column :contacts, :qualification, :string
  end
end
