<?php

    namespace App\Models;

    use Illuminate\Database\Eloquent\Model;

    class PendingSync extends Model {

        public $table = 'pending_sync';

        protected $fillable = [
            'entity_type',
            'payload_json',
            'status',
            'last_error',
        ];

        protected $casts = [
        ];
    }
