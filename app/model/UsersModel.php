<?php
declare (strict_types = 1);

namespace app\model;

use think\Model;

/**
 * @mixin \think\Model
 */
class UsersModel extends Model
{
    // 设置当前模型对应的数据表名称
    protected $table = 'users';

    // 自定义查询方法：根据条件查询用户信息
    public function getAll($field = "*", $condition = [])
    {
        return $this->field($field)->where($condition)->select()->toArray();
    }

    public function getRow($field = "*", $condition = [])
    {
        return $this->field($field)->where($condition)->find();
    }

    // 自定义更新方法：根据条件更新用户信息
    public function updateUser($condition = [], $data = [])
    {
        return $this->where($condition)->update($data);
    }
}
