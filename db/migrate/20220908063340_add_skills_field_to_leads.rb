class AddSkillsFieldToLeads < ActiveRecord::Migration[6.1]
  def change
    add_column :leads, :lead_skills, :string,array: true, default: []
  end
end
