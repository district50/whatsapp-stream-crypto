<!DOCTYPE html>
<html>
<head>
    <title>Импорт Excel файлов</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<div class="container mt-5">
    <div class="row">
        <div class="col-md-10 offset-md-1">
            <div class="card">
                <div class="card-header">
                    <h4>📊 Импорт Excel файлов</h4>
                </div>
                <div class="card-body">
                    @if(session('success'))
                        <div class="alert alert-success alert-dismissible fade show" role="alert">
                            {{ session('success') }}
                            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                        </div>
                    @endif

                    @if(session('error'))
                        <div class="alert alert-danger alert-dismissible fade show" role="alert">
                            {{ session('error') }}
                            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                        </div>
                    @endif

                    @if(session('warnings'))
                        <div class="alert alert-warning">
                            <h6>⚠️ Предупреждения:</h6>
                            <ul class="mb-0">
                                @foreach(session('warnings') as $warning)
                                    <li>{{ $warning }}</li>
                                @endforeach
                            </ul>
                        </div>
                    @endif

                    <div class="row mb-4">
                        <div class="col-md-12">
                            <h6>📈 Статистика в базе данных</h6>
                            <div class="table-responsive">
                                <table class="table table-bordered table-sm table-hover">
                                    <thead class="table-light">
                                    <tr>
                                        <th>Тип данных</th>
                                        <th>Количество записей</th>
                                        <th>Действие</th>
                                    </tr>
                                    </thead>
                                    <tbody>
                                    <tr>
                                        <td>
                                            <span class="badge bg-primary">АМИГО</span>
                                            Гарантийные размеры
                                        </td>
                                        <td>{{ $stats['guarantee_amigo'] }}</td>
                                        <td>
                                            <form action="{{ route('excel-import.clear') }}" method="POST"
                                                  style="display:inline">
                                                @csrf
                                                @method('DELETE')
                                                <input type="hidden" name="type" value="guarantee_amigo">
                                                <button type="submit" class="btn btn-sm btn-danger"
                                                        onclick="return confirm('Удалить все данные АМИГО?')">Очистить
                                                </button>
                                            </form>
                                            <a href="{{ route('excel-import.export', ['type' => 'guarantee_amigo']) }}"
                                               class="btn btn-sm btn-info" target="_blank">Экспорт</a>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td>
                                            <span class="badge bg-success">ФОРУМ</span>
                                            Гарантийные размеры
                                        </td>
                                        <td>{{ $stats['guarantee_forum'] }}</td>
                                        <td>
                                            <form action="{{ route('excel-import.clear') }}" method="POST"
                                                  style="display:inline">
                                                @csrf
                                                @method('DELETE')
                                                <input type="hidden" name="type" value="guarantee_forum">
                                                <button type="submit" class="btn btn-sm btn-danger"
                                                        onclick="return confirm('Удалить все данные ФОРУМ?')">Очистить
                                                </button>
                                            </form>
                                            <a href="{{ route('excel-import.export', ['type' => 'guarantee_forum']) }}"
                                               class="btn btn-sm btn-info" target="_blank">Экспорт</a>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td>
                                            <span class="badge bg-warning text-dark">💰</span>
                                            Сеточный прайс-лист
                                        </td>
                                        <td>{{ $stats['price_matrix'] }}</td>
                                        <td>
                                            <form action="{{ route('excel-import.clear') }}" method="POST"
                                                  style="display:inline">
                                                @csrf
                                                @method('DELETE')
                                                <input type="hidden" name="type" value="price_matrix">
                                                <button type="submit" class="btn btn-sm btn-danger"
                                                        onclick="return confirm('Удалить все цены?')">Очистить
                                                </button>
                                            </form>
                                            <a href="{{ route('excel-import.export', ['type' => 'price_matrix']) }}"
                                               class="btn btn-sm btn-info" target="_blank">Экспорт</a>
                                        </td>
                                    </tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>

                    <hr>

                    <form action="{{ route('excel-import.process') }}" method="POST" enctype="multipart/form-data">
                        @csrf
                        <div class="mb-3">
                            <label for="import_type" class="form-label fw-bold">Тип загрузки</label>
                            <select class="form-select @error('import_type') is-invalid @enderror" id="import_type"
                                    name="import_type" required>
                                <option value="">Выберите тип...</option>
                                <option value="guarantee_amigo">✅ Гарантийные размеры АМИГО</option>
                                <option value="guarantee_forum">✅ Гарантийные размеры ФОРУМ</option>
                                <option value="price_matrix">✅ Сеточный прайс-лист</option>
                            </select>
                            @error('import_type')
                            <div class="invalid-feedback">{{ $message }}</div>
                            @enderror
                        </div>

                        <div class="mb-3">
                            <label for="file" class="form-label fw-bold">Выберите Excel файл</label>
                            <input type="file" class="form-control @error('file') is-invalid @enderror"
                                   id="file" name="file" accept=".xlsx,.xls" required>
                            @error('file')
                            <div class="invalid-feedback">{{ $message }}</div>
                            @enderror
                            <small class="text-muted" id="file_hint">
                                📄 Поддерживаются форматы: .xlsx, .xls (макс. 10MB)
                            </small>
                        </div>

                        <div class="d-grid gap-2 d-md-flex">
                            <button type="submit" class="btn btn-primary btn-lg">
                                <i class="bi bi-upload"></i> Импортировать
                            </button>
                        </div>
                    </form>

                    <hr>

                    <div class="mt-3">
                        <h6>📋 Инструкция по типам файлов:</h6>
                        <div class="table-responsive">
                            <table class="table table-sm table-bordered">
                                <thead class="table-light">
                                <tr>
                                    <th>Тип</th>
                                    <th>Ожидаемые листы</th>
                                    <th>Структура</th>
                                </tr>
                                </thead>
                                <tbody>
                                <tr>
                                    <td><span class="badge bg-primary">АМИГО</span></td>
                                    <td>МИНИ, УНИ 1, УНИ 2, УНИ 2 с пружиной, MG, LVT 32, LVT 45</td>
                                    <td>№п.п. | Название ткани | Категория | ШИРИНА мин/макс | ВЫСОТА мин/макс</td>
                                </tr>
                                <tr>
                                    <td><span class="badge bg-success">ФОРУМ</span></td>
                                    <td>МИНИ, УНИ 1, УНИ 2, МИДЛ 25, МАКСИ 38</td>
                                    <td>№п.п. | Название ткани | Категория | ШИРИНА | ВЫСОТА | ШИРИНА_ALT | ВЫСОТА_ALT
                                    </td>
                                </tr>
                                <tr>
                                    <td><span class="badge bg-warning text-dark">💰</span></td>
                                    <td>Сеточный прайс-лист</td>
                                    <td>Вид продукции | Категория | Матрица цен (ширина х высота)</td>
                                </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
    document.getElementById('import_type').addEventListener('change', function () {
        const hint = document.getElementById('file_hint');
        const type = this.value;

        const hints = {
            'guarantee_amigo': '📄 Файл АМИГО с листами: МИНИ, УНИ 1, УНИ 2, УНИ 2 с пружиной, MG, LVT 32, LVT 45',
            'guarantee_forum': '📄 Файл ФОРУМ с листами: МИНИ, УНИ 1, УНИ 2, МИДЛ 25, МАКСИ 38',
            'price_matrix': '📄 Файл с листом "Сеточный прайс-лист"'
        };

        hint.textContent = hints[type] || '📄 Поддерживаются форматы: .xlsx, .xls (макс. 10MB)';
    });
</script>
</body>
</html>
