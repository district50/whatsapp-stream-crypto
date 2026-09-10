<?php

    namespace App\Models;

    use Illuminate\Database\Eloquent\Model;

    class ImportHistory extends Model {

        public $table = 'import_history';

        protected $fillable = [
            'import_type',
            'filename',
            'records_count',
            'errors_count',
            'errors',
            'status',
            'user_id',
        ];

        protected $casts = [
            'records_count' => 'integer',
            'errors_count' => 'integer',
        ];
    }
