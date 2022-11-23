class AddAltEmailToUsers < ActiveRecord::Migration[6.1]
  def change
    add_column :users, :alt_email, :string, unique: true, limit: 64 
  end
end
