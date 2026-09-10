<?php

    use Illuminate\Database\Migrations\Migration;
    use Illuminate\Database\Schema\Blueprint;
    use Illuminate\Support\Facades\Schema;

    return new class extends Migration {
        public function up() {
            Schema::create( 'fabric_categories', function( Blueprint $table ) {
                $table->id();
                $table->string( 'category_code' );
                $table->string( 'category_name' );
                $table->text( 'description' )->nullable();
                $table->boolean( 'is_active' )->default( true );
                $table->integer( 'discount_limit' )->nullable();
                $table->integer( 'commission_percent' )->default( 10 );
                $table->timestamps();

                $table->unique( 'category_code' );
            } );
        }

        public function down() {
            Schema::dropIfExists( 'fabric_categories' );
        }
    };
