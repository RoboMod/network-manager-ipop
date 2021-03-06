/*
Copyright 2010 Aurélien Gâteau <aurelien.gateau@canonical.com>
Copyright 2011 Rajeesh K Nambiar <rajeeshknambiar@gmail.com>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License as
published by the Free Software Foundation; either version 2 of
the License or (at your option) version 3 or any later version
accepted by the membership of KDE e.V. (or its successor approved
by the membership of KDE e.V.), which shall act as a proxy
defined in Section 14 of version 3 of the license.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#ifndef ADDEDITDELETEBUTTONSET_H
#define ADDEDITDELETEBUTTONSET_H

#include <QWidget>

class QTreeWidget;
class KPushButton;

/**
 * A column of buttons used in to add/edit/remove connections
 */
class AddEditDeleteButtonSet : public QWidget
{
Q_OBJECT
public:
    AddEditDeleteButtonSet(QWidget* parent = 0);

    void setTree(QTreeWidget* tree);

    KPushButton* addButton() const { return mAddButton; }
    KPushButton* editButton() const { return mEditButton; }
    KPushButton* deleteButton() const { return mDeleteButton; }
    KPushButton* importButton() const { return mImportButton; }
    KPushButton* exportButton() const { return mExportButton; }

private slots:
    void updateButtons();

private:
    KPushButton* mAddButton;
    KPushButton* mEditButton;
    KPushButton* mDeleteButton;
    KPushButton* mImportButton;
    KPushButton* mExportButton;

    QTreeWidget* mTree;
};

#endif /* ADDEDITDELETEBUTTONSET_H */
