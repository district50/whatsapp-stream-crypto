<?php

    namespace App\Services;

    use PhpOffice\PhpSpreadsheet\IOFactory;
    use App\Models\GuaranteeSize;
    use App\Models\PriceMatrix;
    use App\Models\ImportHistory;
    use App\Models\FabricCategoryRelation;
    use Illuminate\Support\Facades\Log;
    use Illuminate\Support\Facades\Auth;

    class ExcelImportService {
        private $errors = [];
        private $successCount = 0;
        private $importType;
        private $brand;
        private $filename;

        const TYPE_GUARANTEE_AMIGO = 'guarantee_amigo';
        const TYPE_GUARANTEE_FORUM = 'guarantee_forum';
        const TYPE_PRICE_MATRIX = 'price_matrix';

        public function import( $filePath, $importType, $filename ) {
            $this->errors = [];
            $this->successCount = 0;
            $this->importType = $importType;
            $this->brand = $this->detectBrand( $importType );
            $this->filename = $filename;

            try {
                $spreadsheet = IOFactory::load( $filePath );

                switch( $importType ) {
                    case self::TYPE_GUARANTEE_AMIGO:
                        $this->parseGuaranteeAmigo( $spreadsheet );
                        break;
                    case self::TYPE_GUARANTEE_FORUM:
                        $this->parseGuaranteeForum( $spreadsheet );
                        break;
                    case self::TYPE_PRICE_MATRIX:
                        $this->parsePriceMatrix( $spreadsheet );
                        break;
                    default:
                        throw new \Exception( 'Неизвестный тип импорта' );
                }

                // Сохраняем историю импорта
                $this->saveImportHistory();

                return [
                    'success' => $this->successCount > 0,
                    'success_count' => $this->successCount,
                    'errors' => $this->errors,
                ];

            } catch( \Exception $e ) {
                $this->errors[] = $e->getMessage();
                $this->saveImportHistory();
                throw new \Exception( 'Ошибка при чтении файла: ' . $e->getMessage() );
            }
        }

        private function detectBrand( $importType ) {
            return strpos( $importType, 'amigo' ) !== false ? 'АМИГО' : 'ФОРУМ';
        }

        private function saveImportHistory() {
            ImportHistory::create( [
                'import_type' => $this->importType,
                'filename' => $this->filename,
                'records_count' => $this->successCount,
                'errors_count' => count( $this->errors ),
                'errors' => implode( "\n", $this->errors ),
                'status' => empty( $this->errors ) ? 'success' : ( count( $this->errors ) < 10 ? 'partial' : 'failed' ),
                'user_id' => Auth::id(),
            ] );
        }

        // ========== ПАРСИНГ АМИГО ==========
        private function parseGuaranteeAmigo( $spreadsheet ) {
            $sheetNames = [ 'МИНИ', 'УНИ 1', 'УНИ 2', 'УНИ 2 с пружиной', 'MG', 'LVT 32', 'LVT 45' ];

            foreach( $sheetNames as $sheetName ) {
                try {
                    $worksheet = $spreadsheet->getSheetByName( $sheetName );
                    if( !$worksheet ) continue;

                    $rows = $worksheet->toArray();
                    $this->parseAmigoSheet( $rows, $sheetName );
                } catch( \Exception $e ) {
                    $this->errors[] = "Ошибка в листе {$sheetName}: " . $e->getMessage();
                }
            }
        }

        private function parseAmigoSheet( $rows, $productType ) {
            $dataStart = false;
            foreach( $rows as $rowIndex => $row ) {
                $row = $this->cleanRow( $row );

                if( isset( $row[ 1 ] ) && $row[ 1 ] === '№п.п.' ) {
                    $dataStart = true;
                    continue;
                }

                if( !$dataStart ) continue;

                if( isset( $row[ 1 ] ) && is_numeric( $row[ 1 ] ) && !empty( $row[ 2 ] ) ) {
                    $this->parseAmigoRow( $row, $productType );
                }
            }
        }

        private function parseAmigoRow( $row, $productType ) {
            try {
                $fabricName = $row[ 2 ] ?? '';
                $category = $row[ 3 ] ?? '0';
                $widthRange = $row[ 4 ] ?? '';
                $heightRange = $row[ 5 ] ?? '';

                if( empty( $fabricName ) ) return;

                $widthData = $this->parseRange( $widthRange );
                $heightData = $this->parseRange( $heightRange );

                GuaranteeSize::create( [
                    'product_type' => $productType,
                    'brand' => 'АМИГО',
                    'item_number' => (int)$row[ 1 ],
                    'fabric_name' => trim( $fabricName ),
                    'category' => trim( $category ),
                    'width_min' => $widthData[ 'min' ],
                    'width_max' => $widthData[ 'max' ],
                    'height_min' => $heightData[ 'min' ],
                    'height_max' => $heightData[ 'max' ],
                    'fabric_width' => $this->extractFabricWidth( $fabricName ),
                ] );

                $this->successCount++;
            } catch( \Exception $e ) {
                $this->errors[] = "Ошибка в строке {$row[1]}: " . $e->getMessage();
            }
        }

        // ========== ПАРСИНГ ФОРУМ ==========
        private function parseGuaranteeForum( $spreadsheet ) {
            $sheetNames = [ 'МИНИ', 'УНИ 1', 'УНИ 2', 'МИДЛ 25', 'МАКСИ 38' ];

            foreach( $sheetNames as $sheetName ) {
                try {
                    $worksheet = $spreadsheet->getSheetByName( $sheetName );
                    if( !$worksheet ) continue;

                    $rows = $worksheet->toArray();
                    $this->parseForumSheet( $rows, $sheetName );
                } catch( \Exception $e ) {
                    $this->errors[] = "Ошибка в листе {$sheetName}: " . $e->getMessage();
                }
            }
        }

        private function parseForumSheet( $rows, $productType ) {
            $dataStart = false;

            foreach( $rows as $rowIndex => $row ) {
                $row = $this->cleanRow( $row );

                if( isset( $row[ 0 ] ) && $row[ 0 ] === '№п.п.' ) {
                    $dataStart = true;
                    continue;
                }

                if( !$dataStart ) continue;

                if( isset( $row[ 0 ] ) && is_numeric( $row[ 0 ] ) && !empty( $row[ 1 ] ) ) {
                    $this->parseForumRow( $row, $productType );
                }
            }
        }

        private function parseForumRow( $row, $productType ) {
            try {
                $fabricName = $row[ 1 ] ?? '';
                $category = $row[ 2 ] ?? '0';
                $widthRange = $row[ 3 ] ?? '';
                $heightRange = $row[ 4 ] ?? '';
                $widthRangeAlt = $row[ 5 ] ?? '';
                $heightRangeAlt = $row[ 6 ] ?? '';

                if( empty( $fabricName ) ) return;

                $widthData = $this->parseRange( $widthRange );
                $heightData = $this->parseRange( $heightRange );
                $widthDataAlt = $this->parseRange( $widthRangeAlt );
                $heightDataAlt = $this->parseRange( $heightRangeAlt );

                GuaranteeSize::create( [
                    'product_type' => $productType,
                    'brand' => 'ФОРУМ',
                    'item_number' => (int)$row[ 0 ],
                    'fabric_name' => trim( $fabricName ),
                    'category' => trim( $category ),
                    'width_min' => $widthData[ 'min' ],
                    'width_max' => $widthData[ 'max' ],
                    'height_min' => $heightData[ 'min' ],
                    'height_max' => $heightData[ 'max' ],
                    'width_min_alt' => $widthDataAlt[ 'min' ],
                    'width_max_alt' => $widthDataAlt[ 'max' ],
                    'height_min_alt' => $heightDataAlt[ 'min' ],
                    'height_max_alt' => $heightDataAlt[ 'max' ],
                    'fabric_width' => $this->extractFabricWidth( $fabricName ),
                    'notes' => $this->extractNotes( $row ),
                ] );

                $this->successCount++;
            } catch( \Exception $e ) {
                $this->errors[] = "Ошибка в строке {$row[0]}: " . $e->getMessage();
            }
        }

        // ========== ПАРСИНГ ПРАЙС-ЛИСТА ==========
        private function parsePriceMatrix( $spreadsheet ) {
            $worksheet = $spreadsheet->getSheetByName( 'Сеточный прайс-лист' );
            if( !$worksheet ) {
                throw new \Exception( 'Лист "Сеточный прайс-лист" не найден' );
            }

            $rows = $worksheet->toArray();
            $this->parsePriceMatrixData( $rows );
        }

        private function parsePriceMatrixData( $rows ) {
            $rowIndex = 0;
            $totalRows = count( $rows );

            while( $rowIndex < $totalRows ) {
                $row = $this->cleanRow( $rows[ $rowIndex ] );

                if( isset( $row[ 0 ] ) && strpos( $row[ 0 ], 'Вид продукции:' ) !== false ) {
                    $calculationType = $this->detectCalculationType( $row );
                    $category = $this->findCategory( $rows, $rowIndex );
                    $notes = $this->findNotes( $rows, $rowIndex );
                    $headerRowIndex = $this->findHeaderRow( $rows, $rowIndex );

                    if( $headerRowIndex !== null ) {
                        $widthValues = $this->getWidthValues( $rows[ $headerRowIndex ] );

                        if( !empty( $widthValues ) ) {
                            $rowIndex = $this->parsePriceRows( $rows, $headerRowIndex + 1, $widthValues, $calculationType, $category, $notes );
                            continue;
                        }
                    }
                }

                $rowIndex++;
            }
        }

        private function parsePriceRows( $rows, $startRow, $widthValues, $calculationType, $category, $notes ) {

            $rowIndex = $startRow;
            $parsedCount = 0;
            $maxRows = 25;

            while( $rowIndex < count( $rows ) && $parsedCount < $maxRows ) {
                $row = $this->cleanRow( $rows[ $rowIndex ] );
                $heightValue = $row[ 0 ] ?? '';

                if( !is_numeric( $heightValue ) || $heightValue === '' ) {
                    $heightValue = $row[ 2 ] ?? '';
                    if( !is_numeric( $heightValue ) || $heightValue === '' ) {
                        break;
                    }
                }

                $heightValue = (float)$heightValue;

                for( $col = 1; $col < min( count( $row ), 15 ) && ( $col - 2 ) < count( $widthValues ); $col++ ) {

                    $priceValue = $row[ $col ] ?? '';

                    if( is_string( $priceValue ) ) {
                        $priceValue = (int)str_replace( [ ' ', ',' ], '', $priceValue );
                    }

                    if( is_numeric( $priceValue ) && $priceValue !== '' ) {
                        try {
                            PriceMatrix::create( [
                                'product_type' => 'МИНИ',
                                'calculation_type' => $calculationType,
                                'category' => $category,
                                'width_value' => $widthValues[ $col - 1 ],
                                'height_value' => $heightValue,
                                'price' => (int)$priceValue,
                                'notes' => $notes,
                            ] );
                            $this->successCount++;
                        } catch( \Exception $e ) {
                            $this->errors[] = "Ошибка в строке " . ( $rowIndex + 1 ) . ": " . $e->getMessage();
                        }
                    }
                }

                $rowIndex++;
                $parsedCount++;
            }
            return $rowIndex;
        }

        // ========== ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ ==========
        private function parseRange( $value ) {
            if( empty( $value ) || $value === 'нет' || $value === 'нет.' ) {
                return [ 'min' => null, 'max' => null ];
            }

            $value = trim( str_replace( [ 'см', 'см.', ' ' ], '', $value ) );
            $parts = explode( '/', $value );

            if( count( $parts ) === 2 ) {
                $min = (int)str_replace( ',', '.', trim( $parts[ 0 ] ) );
                $max = (int)str_replace( ',', '.', trim( $parts[ 1 ] ) );
                return [ 'min' => $min, 'max' => $max ];
            }

            return [ 'min' => null, 'max' => null ];
        }

        private function extractFabricWidth( $fabricName ) {
            preg_match( '/(\d+)(?:см|см\.)/', $fabricName, $matches );
            return isset( $matches[ 1 ] ) ? $matches[ 1 ] . 'см' : null;
        }

        private function extractNotes( $row ) {
            foreach( $row as $cell ) {
                if( strpos( $cell, 'Без гарантии' ) !== false ) {
                    return 'Без гарантии';
                }
            }
            return null;
        }

        private function detectCalculationType( $row ) {
            $cellC = $row[ 2 ] ?? '';
            return strpos( $cellC, 'расчет по высоте' ) !== false ? 'height' : 'width';
        }

        private function findCategory( $rows, $currentRow ) {
            for( $i = max( 0, $currentRow - 10 ); $i < $currentRow + 10; $i++ ) {
                $row = $this->cleanRow( $rows[ $i ] );
                if( isset( $row[ 0 ] ) && strpos( $row[ 0 ], 'Категория:' ) !== false ) {
                    return trim( $row[ 2 ] ?? $row[ 1 ] ?? '0' );
                }
            }
            return '0';
        }

        private function findNotes( $rows, $currentRow ) {
            for( $i = max( 0, $currentRow - 5 ); $i <= min( count( $rows ) - 1, $currentRow + 5 ); $i++ ) {
                $row = $this->cleanRow( $rows[ $i ] );
                foreach( $row as $cell ) {
                    if( strpos( $cell, 'Без гарантии' ) !== false ) {
                        return 'Без гарантии';
                    }
                }
            }
            return null;
        }

        private function findHeaderRow( $rows, $startRow ) {
            for( $i = $startRow; $i < min( count( $rows ), $startRow + 10 ); $i++ ) {
                $row = $this->cleanRow( $rows[ $i ] );
                $numberCount = 0;

                for( $col = 2; $col < min( count( $row ), 16 ); $col++ ) {
                    if( is_numeric( $row[ $col ] ?? '' ) && $row[ $col ] !== '' ) {
                        $numberCount++;
                    }
                }

                if( $numberCount > 3 ) {
                    return $i;
                }
            }
            return null;
        }

        private function getWidthValues( $headerRow ) {
            $widthValues = [];
            for( $col = 1; $col < min( count( $headerRow ), 15 ); $col++ ) {
                $value = $headerRow[ $col ] ?? '';
                if( is_numeric( $value ) && $value !== '' ) {
                    $widthValues[] = (float)$value;
                }
            }
            return $widthValues;
        }

        private function cleanRow( $row ) {
            if( !is_array( $row ) ) return [];
            return array_map( function( $cell ) {
                return trim( (string)$cell );
            }, $row );
        }
    }
