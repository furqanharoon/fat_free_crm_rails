class AddTagsFieldToTasks < ActiveRecord::Migration[6.1]
  def change
    add_column :tasks, :task_tag, :string, array: true, default: []
  end
end
