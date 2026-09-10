<?php

    use Illuminate\Database\Migrations\Migration;
    use Illuminate\Database\Schema\Blueprint;
    use Illuminate\Support\Facades\Schema;

    return new class extends Migration {
        public function up() {
            Schema::create( 'product_types', function( Blueprint $table ) {
                $table->id();
                $table->string( 'code' );
                $table->string( 'name' );
                $table->string( 'brand' );
                $table->text( 'description' )->nullable();
                $table->integer( 'min_motorization_width' )->nullable();
                $table->integer( 'max_height_width_ratio' )->default( 3 );
                $table->boolean( 'is_active' )->default( true );
                $table->timestamps();

                $table->unique( [ 'code', 'brand' ] );
            } );
        }

        public function down() {
            Schema::dropIfExists( 'product_types' );
        }
    };
