<?php

    use Illuminate\Database\Migrations\Migration;
    use Illuminate\Database\Schema\Blueprint;
    use Illuminate\Support\Facades\Schema;

    return new class extends Migration {
        public function up() {
            Schema::create( 'import_history', function( Blueprint $table ) {
                $table->id();
                $table->string( 'import_type' );
                $table->string( 'filename' );
                $table->integer( 'records_count' )->default( 0 );
                $table->integer( 'errors_count' )->default( 0 );
                $table->text( 'errors' )->nullable();
                $table->string( 'status' );
                $table->foreignId( 'user_id' )->nullable()->constrained();
                $table->timestamps();

                $table->index( 'import_type' );
                $table->index( 'status' );
            } );
        }

        public function down() {
            Schema::dropIfExists( 'import_history' );
        }
    };
