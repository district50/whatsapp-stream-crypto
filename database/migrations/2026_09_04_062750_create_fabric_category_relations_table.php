<?php

    use Illuminate\Database\Migrations\Migration;
    use Illuminate\Database\Schema\Blueprint;
    use Illuminate\Support\Facades\Schema;

    return new class extends Migration {
        public function up() {
            Schema::create( 'fabric_category_relations', function( Blueprint $table ) {
                $table->id();
                $table->string( 'fabric_name' );
                $table->string( 'category_code' );
                $table->string( 'product_type' )->nullable();
                $table->string( 'brand' )->nullable();
                $table->boolean( 'is_active' )->default( true );
                $table->timestamps();

                $table->index( [ 'fabric_name', 'category_code' ] );
                $table->index( 'product_type' );
                $table->index( 'brand' );
            } );
        }

        public function down() {
            Schema::dropIfExists( 'fabric_category_relations' );
        }
    };
