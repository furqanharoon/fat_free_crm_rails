class AddAccountIdLeads < ActiveRecord::Migration[6.1]
  def change
    add_reference :leads, :account, foreign_key: true, default: nil
  end
end
